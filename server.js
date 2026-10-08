import express from "express";
import multer from "multer";
import cors from "cors";
import { timingSafeEqual } from "node:crypto";
import { GoogleGenAI, Type } from "@google/genai";
import "dotenv/config";

// Version du serveur : visible sur /api/health et dans Paramètres → Prospection → Tester la connexion.
const SERVER_VERSION = "2026.10.08.4";

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 8 * 1024 * 1024 }, // 8 Mo — même limite que côté client GestComPro
});

// CORS : origine configurable via ALLOWED_ORIGIN (ex: "https://mon-gestcompro.exemple.tn"). Laissé
// ouvert (*) par défaut tant que cette variable n'est pas définie — le vrai verrou d'accès reste la
// clé X-App-Api-Key (voir verifierAuthApplicative plus bas), que CORS ne remplace pas : CORS bloque
// seulement les appels faits DEPUIS un navigateur, pas depuis un script/curl qui connaîtrait la clé.
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "";
if (!ALLOWED_ORIGIN) {
  console.warn("⚠️  ALLOWED_ORIGIN non définie — CORS reste ouvert à toute origine (*). Définissez-la une fois votre domaine GestComPro connu pour restreindre l'accès.");
}
app.use(cors(ALLOWED_ORIGIN ? { origin: ALLOWED_ORIGIN } : {}));
// Cross-Origin-Resource-Policy (audit du 26/09) : depuis que le frontend charge en isolation
// stricte (Cross-Origin-Opener-Policy/Cross-Origin-Embedder-Policy, requis par SQLite Wasm/OPFS —
// voir _headers de l'app), le navigateur peut bloquer ses propres appels fetch() vers CE serveur si les
// réponses ne portent pas explicitement cet en-tête, même quand CORS est déjà correctement
// configuré ci-dessus. Sans lui : risque réel que /api/capture, /api/ttn/* et /api/prospection cessent de
// répondre au frontend dès que l'isolation est activée côté navigateur — jamais vérifié en
// conditions réelles (pas de navigateur disponible ici), ajouté par précaution plutôt que découvert
// après coup.
app.use((req, res, next) => { res.setHeader("Cross-Origin-Resource-Policy", "cross-origin"); next(); });
// Envoi de documents par e-mail : PDF en base64 (jusqu'à ~8 Mo) → limite élargie sur cette seule route.
app.use("/api/email", express.json({ limit: "12mb" }));
app.use(express.json());

// ===================== Limitation des appels (audit du 28/09) =====================
// Deux protections contre une clé d'accès perdue (appareil volé) ou un script malveillant, qui
// pourrait sinon vider vos quotas payants Gemini / Google Places :
//  1) par adresse IP : nombre de requêtes maximum sur une fenêtre de 10 minutes, par route ;
//  2) par jour, tous appareils confondus : plafond d'appels Gemini et Google Places (variables
//     IA_MAX_APPELS_JOUR et PLACES_MAX_APPELS_JOUR, 300 par défaut) — au-delà, refus jusqu'à minuit UTC.
// Compteurs en mémoire : remis à zéro si le serveur redémarre (suffisant pour borner les coûts).
app.set("trust proxy", 1); // Render place le serveur derrière un proxy : IP réelle du client dans X-Forwarded-For
function limiteurIP(nom, max, fenetreMin = 10) {
  const fenetre = fenetreMin * 60 * 1000;
  const appels = new Map();
  return (req, res, next) => {
    const ip = req.ip || "inconnue";
    const maintenant = Date.now();
    const liste = (appels.get(ip) || []).filter(t => maintenant - t < fenetre);
    if (liste.length >= max) {
      const attente = Math.ceil((fenetre - (maintenant - liste[0])) / 1000);
      res.set("Retry-After", String(attente));
      return res.status(429).json({ ok: false, message: `Trop de demandes (${nom}) depuis cet appareil : réessayez dans ${Math.ceil(attente / 60)} minute(s).` });
    }
    liste.push(maintenant);
    appels.set(ip, liste);
    if (appels.size > 10000) appels.clear(); // garde-fou mémoire
    next();
  };
}
const PLAFONDS_JOUR = {
  gemini: parseInt(process.env.IA_MAX_APPELS_JOUR || "300", 10),
  places: parseInt(process.env.PLACES_MAX_APPELS_JOUR || "300", 10),
  telia: parseInt(process.env.TEL_IA_MAX_APPELS_JOUR || "100", 10), // recherche de téléphone par Gemini + Google Search
  rechia: parseInt(process.env.RECH_IA_MAX_APPELS_JOUR || "50", 10), // recherche d'entreprises par Gemini + Google Search
  email: parseInt(process.env.EMAIL_MAX_ENVOIS_JOUR || "100", 10), // envoi de documents par e-mail (Gmail : 500/jour max)
};
const compteursJour = { date: "", gemini: 0, places: 0, telia: 0, rechia: 0, email: 0 };
function consommerQuota(type) {
  const jour = new Date().toISOString().slice(0, 10);
  if (compteursJour.date !== jour) { compteursJour.date = jour; Object.keys(PLAFONDS_JOUR).forEach(k => { compteursJour[k] = 0; }); }
  if (compteursJour[type] >= PLAFONDS_JOUR[type]) return false;
  compteursJour[type]++;
  return true;
}
function quotaJour(type) {
  return (req, res, next) => {
    if (!consommerQuota(type)) {
      return res.status(429).json({ ok: false, message: `Plafond journalier atteint (${type === "gemini" ? "analyses IA" : "recherches Google"} : ${PLAFONDS_JOUR[type]} par jour). Réessayez demain, ou relevez la limite sur le serveur.` });
    }
    next();
  };
}
// Filet général : toute route /api, 200 requêtes / 10 min par IP (freine aussi les essais de clé).
app.use("/api", limiteurIP("général", 200));
app.use("/api/ttn", express.text({ type: "*/*", limit: "5mb" })); // le XML TEIF non signé arrive en corps brut, pas en JSON

// Limitation de débit minimaliste (sans dépendance externe non vérifiable ici) : compteur glissant en
// mémoire par IP. Suffisant pour un usage mono-entreprise ; ne survit pas à un redémarrage ni à
// plusieurs instances du serveur — pour un usage à plus grande échelle, préférer un vrai middleware
// dédié (express-rate-limit) avec un store partagé (Redis).
const COMPTEURS_REQUETES = new Map(); // ip -> [timestamps]
function limiterDebit(maxParMinute) {
  return (req, res, next) => {
    const ip = req.ip || req.connection.remoteAddress || "inconnu";
    const maintenant = Date.now();
    const fenetre = 60_000;
    const historique = (COMPTEURS_REQUETES.get(ip) || []).filter(t => maintenant - t < fenetre);
    if (historique.length >= maxParMinute) {
      return res.status(429).json({ ok: false, success: false, message: "Trop de requêtes — réessayez dans une minute." });
    }
    historique.push(maintenant);
    COMPTEURS_REQUETES.set(ip, historique);
    if (COMPTEURS_REQUETES.size > 10000) COMPTEURS_REQUETES.clear(); // audit 08/10 : garde-fou mémoire (Map jamais purgée)
    next();
  };
}
app.use("/api", limiterDebit(30)); // 30 requêtes/minute/IP sur toutes les routes — ajustable si besoin

const GEMINI_API_KEY = process.env.GEMINI_API_KEY || "";
const MODELE = process.env.GEMINI_MODEL || "gemini-2.5-flash";
// Modèle des recherches web (entreprises, téléphone) : le même que GEMINI_MODEL, sauf si GEMINI_MODEL_RECHERCHE
// est défini. Avec Gemini 3.x, la recherche Google intégrée exige la facturation Gemini (non incluse en gratuit).
const MODELE_RECHERCHE = process.env.GEMINI_MODEL_RECHERCHE || MODELE;
if (!GEMINI_API_KEY) {
  console.warn("⚠️  GEMINI_API_KEY absente des variables d'environnement — /api/capture échouera tant qu'elle n'est pas définie.");
}
const ai = new GoogleGenAI({ apiKey: GEMINI_API_KEY });

/* ===================== Schéma de réponse strict =====================
   IMPORTANT : ce schéma — et les noms de champs qu'il produit — doit rester identique à ce
   qu'attend GestComPro côté client (fonction traiterReponseIA() dans index.html). Le front-end a déjà
   tout son écran de vérification, son rapprochement fournisseur/article et ses contrôles automatiques
   câblés sur cette forme exacte de JSON. Si vous renommez un champ ici, renommez-le aussi côté client,
   sinon l'extraction arrivera dans l'app mais les champs resteront vides. */
const schemaExtraction = {
  type: Type.OBJECT,
  properties: {
    typeDocument: { type: Type.STRING, description: "facture_fournisseur, cheque, traite ou inconnu" },
    fournisseurNom: { type: Type.STRING },
    fournisseurMatriculeFiscal: { type: Type.STRING, description: "Format tunisien : 7 chiffres + 3 lettres/chiffres, ex 1234567ABM000" },
    numeroFacture: { type: Type.STRING, description: "Numéro de la facture, ou du chèque/de la traite selon le type de document" },
    dateFacture: { type: Type.STRING, description: "Date d'émission, format AAAA-MM-JJ" },
    dateEcheance: { type: Type.STRING, description: "Format AAAA-MM-JJ, vide si non applicable" },
    devise: { type: Type.STRING },
    lignes: {
      type: Type.ARRAY,
      description: "Lignes d'articles — vide pour un chèque ou une traite",
      items: {
        type: Type.OBJECT,
        properties: {
          designation: { type: Type.STRING },
          reference: { type: Type.STRING },
          quantite: { type: Type.NUMBER },
          prixUnitaireHT: { type: Type.NUMBER },
          tauxTVA: { type: Type.NUMBER },
          remise: { type: Type.NUMBER },
        },
      },
    },
    totalHT: { type: Type.NUMBER },
    totalTVA: { type: Type.NUMBER },
    totalTTC: { type: Type.NUMBER, description: "Pour un chèque/une traite : le montant" },
    contientFODEC: { type: Type.BOOLEAN, description: "true si une ligne \"FODEC\" (1% en général) apparaît explicitement dans le total du document — jamais déduite, uniquement si le mot FODEC ou son montant est visible" },
    montantFODEC: { type: Type.NUMBER, description: "Montant de la ligne FODEC si contientFODEC est true, sinon 0" },
    banque: { type: Type.STRING },
    beneficiaire: { type: Type.STRING },
    tireur: { type: Type.STRING },
    confiances: {
      type: Type.OBJECT,
      description: "Niveau de confiance par champ : haute, moyenne ou faible",
      properties: {
        fournisseurNom: { type: Type.STRING },
        numeroFacture: { type: Type.STRING },
        dateFacture: { type: Type.STRING },
        dateEcheance: { type: Type.STRING },
        totalTTC: { type: Type.STRING },
      },
    },
  },
  required: ["typeDocument"],
};

const promptExtraction = `Tu es un assistant de saisie comptable pour une entreprise tunisienne (GestComPro).
Analyse le document fourni (facture fournisseur, chèque, ou traite/lettre de change) et remplis le schéma JSON demandé, en respectant strictement les noms de champs fournis.
Règles impératives :
- N'invente JAMAIS une valeur absente du document : laisse le champ vide ("" ou 0) et une confiance "faible" plutôt que de deviner.
- Si le document est un chèque ou une traite : remplis "numeroFacture" (numéro du chèque/de la traite), "dateFacture" (date d'émission), "dateEcheance" (échéance, traite uniquement), "totalTTC" (montant), "banque", "beneficiaire" et/ou "tireur" ; laisse "lignes" vide.
- Le matricule fiscal tunisien est 7 chiffres + 3 lettres/chiffres (ex: 1234567ABM000) — ne le confonds jamais avec un numéro de téléphone ou de registre de commerce.
- Les nombres utilisent un point décimal, jamais de virgule ni de séparateur de milliers.
- FODEC : ne coche "contientFODEC" que si une ligne "FODEC" (ou son montant, généralement ~1% du HT) est EXPLICITEMENT visible dans le détail des totaux du document — ne le déduis jamais du type de produit ou d'une supposition.`;

app.post("/api/capture", limiteurIP("analyse de document", 20), verifierAuthIA, quotaJour("gemini"), upload.single("document"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ success: false, error: "Aucun fichier reçu (champ 'document' attendu)." });
    }
    if (!GEMINI_API_KEY) {
      return res.status(500).json({ success: false, error: "GEMINI_API_KEY non configurée côté serveur — voir README_DEPLOIEMENT.md." });
    }

    const filePart = {
      inlineData: {
        data: req.file.buffer.toString("base64"),
        mimeType: req.file.mimetype,
      },
    };

    const response = await ai.models.generateContent({
      model: MODELE,
      contents: [{ text: promptExtraction }, filePart],
      config: {
        temperature: 0.1, // légère marge, jamais 0 strict — évite les réponses vides répétées observées sur certains documents ambigus
        responseMimeType: "application/json",
        responseSchema: schemaExtraction,
      },
    });

    const data = JSON.parse(response.text);
    res.json({ success: true, data });
  } catch (err) {
    console.error("Erreur d'extraction Gemini :", err);
    res.status(500).json({
      success: false,
      error: "Échec de l'analyse IA : " + (err && err.message ? err.message : "erreur inconnue"),
    });
  }
});

// Test réel de Gemini (08/10) : petite requête de quelques jetons pour vérifier en une fois la clé
// IA_API_KEY de l'appareil, la clé GEMINI_API_KEY, le nom du modèle et le quota. Appelé par le Diagnostic.
app.post("/api/ia/test", limiteurIP("test Gemini", 10), verifierAuthIA, quotaJour("gemini"), async (req, res) => {
  if (!GEMINI_API_KEY) return res.status(503).json({ ok: false, message: "GEMINI_API_KEY absente sur Render." });
  const debut = Date.now();
  try {
    const r = await ai.models.generateContent({ model: MODELE, contents: "Réponds uniquement par le mot OK." });
    res.json({ ok: true, modele: MODELE, reponse: String(r.text || "").trim().slice(0, 40), ms: Date.now() - debut });
  } catch (err) {
    console.error("Test Gemini :", err);
    const m = String((err && err.message) || "");
    const message = /API key not valid|API_KEY_INVALID|PERMISSION_DENIED/i.test(m) ? "Clé GEMINI_API_KEY refusée par Google (invalide ou révoquée)."
      : /not found|404/i.test(m) ? `Modèle « ${MODELE} » introuvable : corrigez GEMINI_MODEL sur Render.`
      : /quota|RESOURCE_EXHAUSTED|429/i.test(m) ? "Quota Gemini atteint (gratuit épuisé ou facturation non activée)."
      : "Gemini indisponible : " + m.slice(0, 160);
    res.status(502).json({ ok: false, modele: MODELE, message, ms: Date.now() - debut });
  }
});

// Point de contrôle simple pour vérifier que le serveur tourne et que la clé est bien chargée
// (sans jamais révéler la clé elle-même) — utile pour diagnostiquer un déploiement.
app.get("/api/health", (req, res) => {
  res.json({ ok: true, modele: MODELE, cleConfiguree: !!GEMINI_API_KEY, ttnConfigure: !!(EL_FATOORA_ENDPOINT && SIGNATURE_ENDPOINT),
    version: SERVER_VERSION,
    placesConfigure: !!process.env.GOOGLE_PLACES_API_KEY,
    moteursProspection: { google: !!process.env.GOOGLE_PLACES_API_KEY, osm: true },
    quotasDuJour: { date: compteursJour.date, gemini: `${compteursJour.gemini}/${PLAFONDS_JOUR.gemini}`, places: `${compteursJour.places}/${PLAFONDS_JOUR.places}` } });
});

/* ===================== Relais TTN / El Fatoora — signature XAdES-BES + dépôt =====================
   Implémente exactement l'architecture déjà documentée dans GestComPro elle-même (Paramètres > El
   Fatoora > "Télécharger la note d'architecture") : le navigateur n'envoie plus que le XML TEIF non
   signé (donnée non sensible en soi) et une clé d'API interne à l'application (PAS un secret TTN) ;
   ce serveur, seul, détient le mot de passe El Fatoora et le jeton de signature XAdES-BES, en
   variables d'environnement — jamais dans le navigateur ni dans l'APK Android.
   ⚠️ Comme le rappelle déjà l'application : le format exact du webservice de dépôt El Fatoora n'est
   pas documenté publiquement de façon fiable. Ce relais reproduit fidèlement ce que GestComPro
   fait déjà côté navigateur (mêmes fonctions signerXmlTEIF/transmettreFactureTTN/verifierStatutTTN,
   juste déplacées ici) — à faire valider par TTN/votre prestataire avant tout envoi réel, comme pour
   la version navigateur. */
const EL_FATOORA_ENDPOINT = process.env.EL_FATOORA_ENDPOINT || "";
const EL_FATOORA_ENDPOINT_STATUT = process.env.EL_FATOORA_ENDPOINT_STATUT || "";
const EL_FATOORA_LOGIN = process.env.EL_FATOORA_LOGIN || "";
const EL_FATOORA_PASSWORD = process.env.EL_FATOORA_PASSWORD || "";
const SIGNATURE_ENDPOINT = process.env.SIGNATURE_ENDPOINT || "";
const SIGNATURE_TOKEN = process.env.SIGNATURE_TOKEN || "";
const APP_API_KEY = process.env.APP_API_KEY || "";
// Clé totalement indépendante d'APP_API_KEY (TTN) — l'Analyse IA n'a aucun rapport fonctionnel
// avec la TTN, chacune a désormais son propre secret, sa propre variable d'environnement, et son
// propre en-tête HTTP. Un déploiement peut activer l'une sans jamais configurer l'autre.
const IA_API_KEY = process.env.IA_API_KEY || "";
if (!EL_FATOORA_ENDPOINT || !SIGNATURE_ENDPOINT) {
  console.warn("⚠️  Variables El Fatoora/signature absentes — /api/ttn/* échouera tant qu'elles ne sont pas définies.");
}
if (!APP_API_KEY) {
  console.warn("⚠️  APP_API_KEY absente — /api/ttn/* refusera toute requête tant qu'elle n'est pas définie (voir .env.example).");
}
if (!IA_API_KEY) {
  console.warn("⚠️  IA_API_KEY absente — /api/capture refusera toute requête tant qu'elle n'est pas définie (voir .env.example).");
}

// Authentification applicative interne (PAS un secret TTN) : protège juste l'accès à ce relais.
// Audit 08/10 : comparaison à temps constant (évite de deviner la clé caractère par caractère).
function cleEgale(recue, attendue) {
  if (!attendue || typeof recue !== "string") return false;
  const a = Buffer.from(recue), b = Buffer.from(attendue);
  return a.length === b.length && timingSafeEqual(a, b);
}
function verifierAuthApplicative(req, res, next) {
  const cle = req.header("X-App-Api-Key");
  if (!cleEgale(cle, APP_API_KEY)) return res.status(401).json({ ok: false, message: "Non autorisé (X-App-Api-Key manquante ou incorrecte)." });
  next();
}
// Authentification dédiée à l'Analyse IA — volontairement séparée de verifierAuthApplicative
// (TTN) : en-tête distinct, clé distincte, aucune des deux fonctions ne se lit ni ne s'utilise.
function verifierAuthIA(req, res, next) {
  const cle = req.header("X-Ia-Api-Key");
  if (!cleEgale(cle, IA_API_KEY)) return res.status(401).json({ ok: false, message: "Non autorisé (X-Ia-Api-Key manquante ou incorrecte)." });
  next();
}
// Extraction simple par expression régulière plutôt qu'un vrai parseur XML : suffisant pour les
// quelques balises attendues (NumeroSuivi/Statut/Erreur/Fault), et évite une dépendance
// supplémentaire pour un format de réponse que TTN ne documente de toute façon pas officiellement
// (même limite, déjà assumée, que le code navigateur existant — voir transmettreFactureTTN()).
function extraireBalise(xml, nom) {
  const m = xml.match(new RegExp(`<${nom}[^>]*>([\\s\\S]*?)</${nom}>`, "i"));
  return m ? m[1].trim() : null;
}

app.post("/api/ttn/signer-et-envoyer", limiteurIP("envoi TTN", 30), verifierAuthApplicative, async (req, res) => {
  try {
    const xmlNonSigne = req.body;
    if (!xmlNonSigne || typeof xmlNonSigne !== "string" || !xmlNonSigne.trim()) {
      return res.status(400).json({ ok: false, message: "Corps de requête vide (XML TEIF non signé attendu)." });
    }
    if (!EL_FATOORA_ENDPOINT || !SIGNATURE_ENDPOINT) {
      return res.status(500).json({ ok: false, message: "Relais TTN non configuré côté serveur (variables d'environnement manquantes)." });
    }

    // 1) Signature XAdES-BES via le service TunTrust/DigiGo configuré
    let xmlSigne;
    try {
      const repSignature = await fetch(SIGNATURE_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "application/xml; charset=utf-8", "Authorization": `Bearer ${SIGNATURE_TOKEN}` },
        body: xmlNonSigne,
      });
      if (!repSignature.ok) {
        const detail = await repSignature.text().catch(() => "");
        return res.status(502).json({ ok: false, message: `Échec de signature électronique (HTTP ${repSignature.status})${detail ? " — " + detail.slice(0, 300) : ""}.` });
      }
      xmlSigne = await repSignature.text();
    } catch (err) {
      return res.status(502).json({ ok: false, message: "Service de signature injoignable : " + err.message });
    }

    // 2) Dépôt SOAP à El Fatoora (TTN)
    const esc = (s) => String(s == null ? "" : s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    const enveloppeSoap = `<?xml version="1.0" encoding="UTF-8"?>
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
  <soapenv:Header>
    <Authentification>
      <Identifiant>${esc(EL_FATOORA_LOGIN)}</Identifiant>
      <MotDePasse>${esc(EL_FATOORA_PASSWORD)}</MotDePasse>
    </Authentification>
  </soapenv:Header>
  <soapenv:Body>
    <DeposerFacture><FichierXML><![CDATA[${xmlSigne}]]></FichierXML></DeposerFacture>
  </soapenv:Body>
</soapenv:Envelope>`;

    let texteReponse;
    try {
      const repTTN = await fetch(EL_FATOORA_ENDPOINT, {
        method: "POST",
        headers: { "Content-Type": "text/xml; charset=utf-8", "SOAPAction": "DeposerFacture" },
        body: enveloppeSoap,
      });
      texteReponse = await repTTN.text();
    } catch (err) {
      // Cas ambigu : si la coupure survient après réception par la TTN mais avant la réponse, on ne
      // peut pas savoir si le document a malgré tout été reçu — même limite honnête que côté
      // navigateur (voir envoyerFactureTTN() dans index.html).
      return res.status(502).json({ ok: false, ambigu: true, message: "Transmission à la TTN impossible : " + err.message + " Si cette erreur survient après une coupure réseau, le document a peut-être tout de même été reçu par la TTN — vérifiez sur le portail El Fatoora avant de retransmettre." });
    }

    const erreur = extraireBalise(texteReponse, "Erreur") || extraireBalise(texteReponse, "Fault");
    if (erreur) {
      return res.json({ ok: true, succes: false, statut: "REJETE", message: erreur });
    }
    res.json({
      ok: true,
      succes: true,
      numeroSuivi: extraireBalise(texteReponse, "NumeroSuivi"),
      statut: extraireBalise(texteReponse, "Statut") || "EN_ATTENTE",
    });
  } catch (err) {
    console.error("Erreur relais TTN (signer-et-envoyer) :", err);
    res.status(500).json({ ok: false, message: err.message || "Erreur inconnue." });
  }
});

app.get("/api/ttn/statut", limiteurIP("statut TTN", 60), verifierAuthApplicative, async (req, res) => {
  try {
    const numeroSuivi = req.query.numeroSuivi;
    if (!numeroSuivi) return res.status(400).json({ ok: false, message: "Paramètre numeroSuivi manquant." });
    if (!EL_FATOORA_ENDPOINT_STATUT) return res.status(500).json({ ok: false, message: "EL_FATOORA_ENDPOINT_STATUT non configuré côté serveur." });
    const headers = {};
    if (EL_FATOORA_LOGIN) headers["Authorization"] = "Basic " + Buffer.from(`${EL_FATOORA_LOGIN}:${EL_FATOORA_PASSWORD}`).toString("base64");
    const repTTN = await fetch(`${EL_FATOORA_ENDPOINT_STATUT}?numeroSuivi=${encodeURIComponent(numeroSuivi)}`, { headers });
    if (!repTTN.ok) return res.status(502).json({ ok: false, message: `Vérification de statut impossible (HTTP ${repTTN.status}).` });
    const data = await repTTN.json();
    res.json({ ok: true, statut: data && data.statut ? data.statut : null, brut: data });
  } catch (err) {
    console.error("Erreur relais TTN (statut) :", err);
    res.status(500).json({ ok: false, message: err.message || "Erreur inconnue." });
  }
});


// ===================== Recherche OpenStreetMap (utilisée par la prospection) =====================
// Correctif 04/10 : le serveur public Nominatim refusait les requêtes venant de Render (réponse 429,
// adresses IP partagées par de nombreux services). La recherche n'en dépend plus :
//   1) localisation de la zone par Overpass (lieu ou limite administrative portant ce nom, accents
//      et majuscules ignorés), sinon Photon (géocodeur OpenStreetMap), sinon Nominatim en dernier ;
//   2) établissements du segment par Overpass, autour du lieu ou dans la limite trouvée ;
//   3) repli recherche texte par Photon, puis Nominatim.
// Une panne d'un service n'arrête plus la recherche : elle est signalée dans les notes.
const NOMINATIM = "https://nominatim.openstreetmap.org";
const PHOTON = "https://photon.komoot.io/api/";
const OVERPASS = [
  "https://overpass-api.de/api/interpreter",
  "https://overpass.private.coffee/api/interpreter",
  "https://maps.mail.ru/osm/tools/overpass/api/interpreter",
];
const BBOX_TUNISIE = [30.2, 7.5, 37.6, 11.7]; // sud, ouest, nord, est
const CONTACT = process.env.OSM_CONTACT || "";
const USER_AGENT = "GestComPro/1.0 (prospection commerciale" + (CONTACT ? "; " + CONTACT : "") + ")";

const pause = (ms) => new Promise((r) => setTimeout(r, ms));
let derniereNominatim = 0;
let fileNominatim = Promise.resolve();
function espacerNominatim(delaiMs = 1100) {
  const tache = fileNominatim.then(async () => {
    const attendre = derniereNominatim + delaiMs - Date.now();
    if (attendre > 0) await pause(attendre);
    derniereNominatim = Date.now();
  });
  fileNominatim = tache.catch(() => {});
  return tache;
}
async function fetchAvecDelai(fetchImpl, url, options = {}, delaiMs = 30000) {
  const ctrl = new AbortController();
  const t = setTimeout(() => ctrl.abort(), delaiMs);
  try { return await fetchImpl(url, { ...options, signal: ctrl.signal }); }
  finally { clearTimeout(t); }
}

// Nom → expression régulière tolérante : accents, majuscules, tirets, apostrophes et espaces.
function motifNom(nom) {
  const classes = { a: "[aàâä]", e: "[eéèêë]", i: "[iîï]", o: "[oôö]", u: "[uùûü]", c: "[cç]" };
  const base = String(nom || "").normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase().trim();
  let out = "";
  for (const ch of base) {
    if (/[a-z]/.test(ch)) out += classes[ch] || ch;
    else if (/[0-9]/.test(ch)) out += ch;
    else if (/[\s'’\-]/.test(ch)) { if (!out.endsWith("[-' ]*")) out += "[-' ]*"; }
  }
  return out;
}

async function appelerOverpass(requete, fetchImpl = fetch, serveurs = OVERPASS, delaiRelance = 2000, delaiMax = 35000) {
  let derniereErreur = null;
  // Chaque serveur est essayé deux fois (surcharge passagère fréquente : 429 / 504).
  const essais = serveurs.flatMap((u) => [u, u]);
  for (let i = 0; i < essais.length; i++) {
    const url = essais[i];
    if (i % 2 === 1 && derniereErreur && /Overpass (429|50\d)/.test(derniereErreur.message)) await pause(delaiRelance);
    else if (i % 2 === 1) continue;
    try {
      const r = await fetchAvecDelai(fetchImpl, url, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": USER_AGENT },
        body: "data=" + encodeURIComponent(requete),
      }, delaiMax);
      if (r.status === 429 || r.status >= 500) { derniereErreur = new Error("Overpass " + r.status); continue; }
      if (!r.ok) throw new Error("Overpass a répondu " + r.status);
      const j = await r.json();
      return Array.isArray(j.elements) ? j.elements : [];
    } catch (err) { derniereErreur = err.name === "AbortError" || /aborted/i.test(err.message) ? new Error("Overpass 504 (délai dépassé)") : err; }
  }
  throw derniereErreur || new Error("Overpass indisponible");
}

const RANG_LIEU = { city: 1, town: 2, village: 3, suburb: 4, quarter: 5, neighbourhood: 6, hamlet: 7, locality: 8 };
const RAYON_LIEU = { city: 8000, town: 5000, village: 3000, suburb: 2500, quarter: 2000, neighbourhood: 1500, hamlet: 2000, locality: 2500 };
// Localisation par Overpass : lieux (node place=…) et limites administratives portant ce nom.
async function localiserParOverpass(nom, portee, fetchImpl, serveurs) {
  const motif = motifNom(nom);
  if (!motif || motif.length < 3) return null;
  const [s, w, n, e] = BBOX_TUNISIE;
  const variantes = (sel) => ["name:fr", "name", "name:en"].map((k) => `${sel}["${k}"~"^${motif}$",i](${s},${w},${n},${e});`).join("");
  // Gouvernorat (correctif 04/10) : les limites de niveau 4 s'appellent « Gouvernorat de Monastir »,
  // « Monastir Governorate »… — on accepte donc un nom qui CONTIENT le nom saisi, au niveau 4 seulement.
  const partieGouv = portee === "gouvernorat" ? ["name:fr", "name:en"].map((k) => `relation["boundary"="administrative"]["admin_level"="4"]["${k}"~"${motif}",i](${s},${w},${n},${e});`).join("") : "";
  const q = `[out:json][timeout:25];(${partieGouv}${variantes('node["place"~"^(city|town|village|suburb|quarter|neighbourhood|hamlet|locality)$"]')}${variantes('relation["boundary"="administrative"]')});out tags center bb 20;`;
  const els = await appelerOverpass(q, fetchImpl, serveurs);
  const rels = els.filter((x) => x.type === "relation" && x.bounds);
  const lieux = els.filter((x) => x.type === "node" && x.tags && x.tags.place).sort((a, b) => (RANG_LIEU[a.tags.place] || 9) - (RANG_LIEU[b.tags.place] || 9));
  if (portee === "gouvernorat") {
    const r = rels.filter((x) => String(x.tags.admin_level) === "4")[0];
    if (r) return { bbox: [r.bounds.minlat, r.bounds.minlon, r.bounds.maxlat, r.bounds.maxlon], nom, source: "Overpass", niveau: "gouvernorat" };
    // Pas de limite de gouvernorat trouvée : grande zone autour du chef-lieu plutôt que la seule commune
    const p = lieux[0];
    if (p) return { lat: p.lat, lon: p.lon, rayon: 30000, nom, source: "Overpass", niveau: "approx" };
  }
  if (lieux.length) { const p = lieux[0]; return { lat: p.lat, lon: p.lon, rayon: RAYON_LIEU[p.tags.place] || 4000, nom, source: "Overpass" }; }
  const r = rels.sort((a, b) => (Number(b.tags.admin_level) || 0) - (Number(a.tags.admin_level) || 0))[0];
  if (r) return { bbox: [r.bounds.minlat, r.bounds.minlon, r.bounds.maxlat, r.bounds.maxlon], nom, source: "Overpass" };
  return null;
}
async function localiserParPhoton(zone, fetchImpl) {
  const [s, w, n, e] = BBOX_TUNISIE;
  const url = `${PHOTON}?q=${encodeURIComponent(zone + " Tunisie")}&limit=5&lang=fr&bbox=${w},${s},${e},${n}`;
  const r = await fetchAvecDelai(fetchImpl, url, { headers: { "User-Agent": USER_AGENT } }, 15000);
  if (!r.ok) throw new Error("Photon a répondu " + r.status);
  const j = await r.json();
  const f = j && Array.isArray(j.features) && (j.features.find((x) => x.properties && String(x.properties.countrycode || "").toUpperCase() === "TN") || null);
  if (!f || !f.geometry) return null;
  const [lon, lat] = f.geometry.coordinates;
  const ext = f.properties && f.properties.extent; // [ouest, nord, est, sud]
  if (Array.isArray(ext) && ext.length === 4) return { bbox: bboxCorrigee([ext[3], ext[1], ext[0], ext[2]]), nom: zone, source: "Photon" };
  return { lat, lon, rayon: 4000, nom: zone, source: "Photon" };
}
async function localiserParNominatim(zone, fetchImpl, delaiMs) {
  await espacerNominatim(delaiMs);
  const url = `${NOMINATIM}/search?q=${encodeURIComponent(zone + " Tunisie")}&format=jsonv2&limit=1&countrycodes=tn&accept-language=fr`;
  const r = await fetchAvecDelai(fetchImpl, url, { headers: { "User-Agent": USER_AGENT } }, 15000);
  if (!r.ok) throw new Error("Nominatim a répondu " + r.status);
  const j = await r.json();
  const x = Array.isArray(j) && j[0];
  if (x && x.boundingbox && x.boundingbox.length === 4) return { bbox: bboxCorrigee(x.boundingbox.map(Number)), nom: zone, source: "Nominatim" };
  return null;
}
const cacheZones = new Map();
async function localiserZone({ ville, gouvernorat, portee }, fetchImpl = fetch, options = {}) {
  const nom = portee === "gouvernorat" ? (gouvernorat || ville) : (ville || gouvernorat);
  const cle = (portee || "") + "|" + String(nom).toLowerCase() + "|" + String(gouvernorat || "").toLowerCase();
  const c = cacheZones.get(cle);
  if (c && c.expire > Date.now()) return { zone: c.valeur, notes: [] };
  const notes = [];
  const essais = [
    () => localiserParOverpass(nom, portee, fetchImpl, options.serveursOverpass || OVERPASS),
    () => localiserParPhoton([ville, gouvernorat].filter(Boolean).join(" "), fetchImpl),
    () => localiserParNominatim([ville, gouvernorat].filter(Boolean).join(" "), fetchImpl, options.delaiNominatim),
  ];
  for (const essai of essais) {
    try { const z = await essai(); if (z) { cacheZones.set(cle, { valeur: z, expire: Date.now() + 7 * 24 * 3600 * 1000 }); return { zone: z, notes }; } }
    catch (err) { notes.push(err.message); }
  }
  return { zone: null, notes };
}
// Compatibilité avec la route de test et les anciens appels
async function geocoderZone(zone, fetchImpl = fetch) { const r = await localiserZone({ ville: zone }, fetchImpl); return r.zone; }

function bboxCorrigee([s, n, w, e], minDemi = 0.03, maxDemi = 0.7) {
  const cLat = (s + n) / 2, cLon = (w + e) / 2;
  const dLat = Math.min(maxDemi, Math.max(minDemi, (n - s) / 2));
  const dLon = Math.min(maxDemi, Math.max(minDemi, (e - w) / 2));
  return [cLat - dLat, cLon - dLon, cLat + dLat, cLon + dLon];
}
const RE_CLE = /^[a-z][a-z0-9_:]{0,30}$/;
const RE_VAL = /^[a-z0-9_]{1,40}$/;
function filtresValides(osm) {
  if (!Array.isArray(osm)) return [];
  return osm.slice(0, 8).map((f) => {
    if (!f || !RE_CLE.test(String(f.cle || ""))) return null;
    const valeurs = (Array.isArray(f.valeurs) ? f.valeurs : []).map(String).filter((v) => RE_VAL.test(v)).slice(0, 12);
    return { cle: f.cle, valeurs };
  }).filter(Boolean);
}
// Zone : {bbox:[s,w,n,e]} ou {lat, lon, rayon} (mètres)
function construireRequeteOverpass(zone, filtres, limite = 60) {
  const ou = zone.bbox ? zone.bbox.map((v) => Number(v).toFixed(5)).join(",")
    : `around:${Math.round(zone.rayon || 4000)},${Number(zone.lat).toFixed(5)},${Number(zone.lon).toFixed(5)}`;
  // Correctif 04/10 : beaucoup d'établissements (stations-service, agences) n'ont qu'une enseigne
  // (brand) ou un exploitant, sans « name » : ils étaient écartés. Le filtre « nommé » est appliqué
  // ensuite (nom, enseigne ou exploitant).
  const lignes = filtres.map((f) => `nwr${selecteurFiltre(f)}(${ou});`);
  // Le double de la limite : les éléments sans nom ni enseigne sont écartés ensuite.
  return `[out:json][timeout:25];(${lignes.join("")});out center tags ${Math.max(10, Math.min(200, limite * 2))};`;
}
function ficheDepuisOverpass(el, villeParDefaut = "") {
  const t = el.tags || {};
  const rue = [t["addr:housenumber"], t["addr:street"]].filter(Boolean).join(" ");
  const adresse = [rue, t["addr:suburb"], t["addr:city"] || t["addr:town"] || t["addr:village"]].filter(Boolean).join(", ");
  const lat = el.lat ?? (el.center && el.center.lat) ?? null;
  const lon = el.lon ?? (el.center && el.center.lon) ?? null;
  return {
    placeId: "", osmId: el.type && el.id ? `${el.type}/${el.id}` : "",
    nom: t["name:fr"] || t.name || [t.brand, t.operator && t.operator !== t.brand ? t.operator : ""].filter(Boolean).join(" — ") || "",
    adresse, ville: t["addr:city"] || t["addr:town"] || t["addr:village"] || villeParDefaut,
    tel: t.phone || t["contact:phone"] || t.mobile || t["contact:mobile"] || "",
    siteWeb: t.website || t["contact:website"] || "",
    note: null, nbAvis: null,
    lat: lat !== null ? Number(lat) : null, lng: lon !== null ? Number(lon) : null, statutGoogle: "",
  };
}
const norm = (v) => String(v || "").toLowerCase().normalize("NFD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]/g, "");
function dedoublonner(fiches) {
  const vus = new Set();
  return fiches.filter((f) => {
    const cle = f.placeId || f.osmId || (norm(f.nom) + "|" + (f.lat !== null && f.lng !== null ? f.lat.toFixed(4) + "," + f.lng.toFixed(4) : norm(f.adresse)));
    if (vus.has(cle)) return false;
    vus.add(cle); return true;
  });
}
// Correctif 04/10 (3) : le repli texte renvoyait des stations de louage et des stations d'Algérie
// (le rectangle de la Tunisie déborde sur Annaba). Désormais : filtre de catégorie (osm_tag), pays TN
// seulement, gouvernorat vérifié, distance maximale autour de la zone, noms en français.
function distanceKm(a, b, c, d) { const r = Math.PI / 180, x = (d - b) * r * Math.cos(((a + c) / 2) * r), y = (c - a) * r; return Math.sqrt(x * x + y * y) * 6371; }
async function rechercheTextePhoton({ requete, zoneTexte, zone, limite, filtres, gouvernorat, portee }, fetchImpl) {
  const [s, w, n, e] = zone && zone.bbox ? zone.bbox : BBOX_TUNISIE;
  const centre = zone && zone.lat ? `&lat=${zone.lat}&lon=${zone.lon}` : "";
  const tags = (filtres || []).flatMap((f) => f.valeurs.length ? f.valeurs.map((v) => `&osm_tag=${encodeURIComponent(f.cle + ":" + v)}`) : [`&osm_tag=${encodeURIComponent(f.cle)}`]).slice(0, 12).join("");
  const texte = tags ? zoneTexte : requete + " " + zoneTexte;
  const url = `${PHOTON}?q=${encodeURIComponent(texte)}&limit=${Math.min(50, limite * 2)}&lang=fr&bbox=${w},${s},${e},${n}${centre}${tags}`;
  const r = await fetchAvecDelai(fetchImpl, url, { headers: { "User-Agent": USER_AGENT } }, 20000);
  if (!r.ok) throw new Error("Photon a répondu " + r.status);
  const j = await r.json();
  return (j && Array.isArray(j.features) ? j.features : []).map((f) => {
    const p = f.properties || {}, c = (f.geometry && f.geometry.coordinates) || [];
    return {
      placeId: "", osmId: p.osm_type && p.osm_id ? `${({N:"node",W:"way",R:"relation"})[p.osm_type] || p.osm_type}/${p.osm_id}` : "",
      nom: p.name || "", adresse: [[p.housenumber, p.street].filter(Boolean).join(" "), p.city || p.district].filter(Boolean).join(", "),
      ville: p.city || p.district || "", tel: "", siteWeb: "", note: null, nbAvis: null,
      lat: c[1] ?? null, lng: c[0] ?? null, statutGoogle: "",
      _pays: p.countrycode || "", _region: p.state || "",
    };
  }).filter((x) => {
    if (!x.nom) return false;
    if (x._pays && x._pays.toUpperCase() !== "TN") return false;
    if (gouvernorat && x._region && !norm(x._region).includes(norm(gouvernorat)) && !norm(gouvernorat).includes(norm(x._region))) return false;
    if (zone && zone.lat && x.lat !== null && x.lng !== null) {
      const max = portee === "gouvernorat" ? 45 : Math.max(6, (zone.rayon || 4000) / 1000 * 1.6);
      if (distanceKm(zone.lat, zone.lon, x.lat, x.lng) > max) return false;
    }
    return true;
  }).map(({ _pays, _region, ...x }) => x);
}
async function rechercheTexteNominatim({ requete, zoneTexte, limite }, fetchImpl, delaiMs) {
  await espacerNominatim(delaiMs);
  const url = `${NOMINATIM}/search?q=${encodeURIComponent(requete + " " + zoneTexte + " Tunisie")}&format=jsonv2&addressdetails=1&extratags=1&limit=${Math.min(40, limite)}&countrycodes=tn&accept-language=fr`;
  const r = await fetchAvecDelai(fetchImpl, url, { headers: { "User-Agent": USER_AGENT } }, 20000);
  if (!r.ok) throw new Error("Nominatim a répondu " + r.status);
  const j = await r.json();
  return (Array.isArray(j) ? j : []).map((x) => ({
    placeId: "", osmId: x.osm_type && x.osm_id ? `${x.osm_type}/${x.osm_id}` : "",
    nom: x.name || String(x.display_name || "").split(",")[0], adresse: x.display_name || "",
    ville: (x.address && (x.address.town || x.address.city || x.address.village)) || "",
    tel: (x.extratags && (x.extratags.phone || x.extratags["contact:phone"])) || "",
    siteWeb: (x.extratags && (x.extratags.website || x.extratags["contact:website"])) || "",
    note: null, nbAvis: null, lat: parseFloat(x.lat) || null, lng: parseFloat(x.lon) || null, statutGoogle: "",
  })).filter((x) => x.nom);
}
function selecteurFiltre(f) {
  if (!f.valeurs.length) return `["${f.cle}"]["name"]`;
  if (f.valeurs.length === 1) return `["${f.cle}"="${f.valeurs[0]}"]`;
  return `["${f.cle}"~"^(${f.valeurs.join("|")})$"]`;
}
// Codes ISO 3166-2 des gouvernorats (étiquette « ISO3166-2 » des limites administratives OSM).
const ISO_GOUVERNORATS = {
  "tunis":"TN-11","ariana":"TN-12","benarous":"TN-13","lamanouba":"TN-14","manouba":"TN-14",
  "nabeul":"TN-21","zaghouan":"TN-22","bizerte":"TN-23",
  "beja":"TN-31","jendouba":"TN-32","lekef":"TN-33","kef":"TN-33","siliana":"TN-34",
  "kairouan":"TN-41","kasserine":"TN-42","sidibouzid":"TN-43",
  "sousse":"TN-51","monastir":"TN-52","mahdia":"TN-53","sfax":"TN-61",
  "gafsa":"TN-71","tozeur":"TN-72","kebili":"TN-73",
  "gabes":"TN-81","medenine":"TN-82","tataouine":"TN-83",
};
// Gouvernorat entier (correctif 04/10, 2) : recherche DANS le polygone officiel du gouvernorat
// (zone Overpass trouvée par code ISO ou par nom de niveau 4), en une seule requête rapide.
// Renvoie null si la limite n'existe pas dans OpenStreetMap (le calcul habituel prend alors le relais).
async function rechercheGouvernoratParZone(gouvernorat, filtres, limite, fetchImpl, serveurs) {
  const iso = ISO_GOUVERNORATS[norm(gouvernorat)];
  const motif = motifNom(gouvernorat);
  if (!motif) return null;
  // Correctif 04/10 (3) : la recherche d'une zone par nom parcourt toutes les limites de niveau 4 du
  // monde (requête lourde → 504). Le code ISO, indexé, est utilisé seul quand il est connu.
  const zones = iso ? `area["ISO3166-2"="${iso}"];`
    : `area["boundary"="administrative"]["admin_level"="4"]["name:fr"~"${motif}",i];area["boundary"="administrative"]["admin_level"="4"]["name:en"~"${motif}",i];`;
  const lignes = filtres.map((f) => `nwr${selecteurFiltre(f)}(area.g);`);
  const q = `[out:json][timeout:60];(${zones})->.g;.g out tags;(${lignes.join("")});out center tags ${Math.max(20, Math.min(400, limite * 3))};`;
  const els = await appelerOverpass(q, fetchImpl, serveurs.slice(0, 2), 2000, 65000);
  const aires = els.filter((x) => x.type === "area");
  if (!aires.length) return null;
  const t = aires[0].tags || {};
  return { elements: els.filter((x) => x.type !== "area"), libelle: t["name:fr"] || t.name || ("Gouvernorat de " + gouvernorat) };
}

// Point d'entrée. Ne lève jamais d'erreur : en cas de panne générale, renvoie 0 résultat et des notes.
async function rechercheOSM({ requete, ville, gouvernorat, portee, osm, limite = 40 }, fetchImpl = fetch, options = {}) {
  const filtres = filtresValides(osm);
  const notes = [];
  if (portee === "gouvernorat" && gouvernorat && filtres.length) {
    try {
      const g = await rechercheGouvernoratParZone(gouvernorat, filtres, limite, fetchImpl, options.serveursOverpass || OVERPASS);
      if (g) {
        const fiches = dedoublonner(g.elements.map((e) => ficheDepuisOverpass(e, "")).filter((f) => f.nom));
        if (fiches.length) return { resultats: fiches.slice(0, limite), methode: "overpass", notes, zoneUtilisee: g.libelle + " (limite officielle)" };
        notes.push("aucun établissement de ce type référencé dans " + g.libelle);
      } else notes.push("limite du gouvernorat absente d'OpenStreetMap : zone approximative utilisée");
    } catch (err) { notes.push("Overpass (gouvernorat) : " + err.message); }
  }
  const zoneTexte = [...new Set([ville, gouvernorat].filter(Boolean))].join(" ");
  const loc = await localiserZone({ ville, gouvernorat, portee }, fetchImpl, options);
  const zone = loc.zone;
  if (!zone) notes.push("zone introuvable sur OpenStreetMap (" + (loc.notes.join(" ; ") || "aucune correspondance") + ")");
  if (filtres.length && zone) {
    try {
      const els = await appelerOverpass(construireRequeteOverpass(zone, filtres, limite), fetchImpl, options.serveursOverpass || OVERPASS);
      const fiches = dedoublonner(els.map((e) => ficheDepuisOverpass(e, portee === "gouvernorat" ? "" : (ville || gouvernorat))).filter((f) => f.nom));
      const zoneUtilisee = zone.bbox ? `${zone.nom} (${zone.niveau === "gouvernorat" ? "limite du gouvernorat" : "zone"}, ${zone.source})` : `${zone.nom} (${Math.round((zone.rayon || 4000) / 1000)} km autour, ${zone.source})`;
      if (fiches.length) return { resultats: fiches.slice(0, limite), methode: "overpass", notes, zoneUtilisee };
      notes.push("aucun établissement de ce type référencé dans la zone");
    } catch (err) { notes.push("Overpass : " + err.message); }
  }
  for (const [nomService, f] of [["Photon", () => rechercheTextePhoton({ requete, zoneTexte, zone, limite, filtres, gouvernorat, portee }, fetchImpl)],
                                 ["Nominatim", () => rechercheTexteNominatim({ requete, zoneTexte, limite }, fetchImpl, options.delaiNominatim)]]) {
    try {
      const res = dedoublonner(await f());
      if (res.length) return { resultats: res.slice(0, limite), methode: "texte", notes, zoneUtilisee: (zone ? zone.nom : zoneTexte) + " (recherche de secours " + nomService + ", moins précise)" };
    } catch (err) { notes.push(nomService + " : " + err.message); }
  }
  return { resultats: [], methode: "aucune", notes };
}

// ===================== Prospection (recherche d'entreprises, mise à jour, analyse IA) =====================
// Protégé par la même clé que l'Analyse IA (X-Ia-Api-Key) : ce sont des appels IA / données externes
// déclenchés depuis GestComPro, pas de la synchro. Google Places (API "New") si GOOGLE_PLACES_API_KEY
// est définie, sinon repli gratuit sur OpenStreetMap (Nominatim) — moins complet, souvent sans téléphone.
const GOOGLE_PLACES_API_KEY = process.env.GOOGLE_PLACES_API_KEY || "";
const CHAMPS_PLACE = "id,displayName,formattedAddress,nationalPhoneNumber,internationalPhoneNumber,location,rating,userRatingCount,websiteUri,businessStatus";
// ---------- Gemini + recherche Google (gratuit dans le quota Gemini, sans carte bancaire) ----------
// Appel REST direct (indépendant de la version du SDK). Renvoie le texte et les sources web consultées.
async function geminiRechercheWeb(prompt) {
  const url = `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(MODELE_RECHERCHE)}:generateContent`;
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json", "x-goog-api-key": GEMINI_API_KEY },
    body: JSON.stringify({ contents: [{ role: "user", parts: [{ text: prompt }] }], tools: [{ google_search: {} }], generationConfig: { temperature: 0.1 } }),
  });
  const j = await r.json().catch(() => ({}));
  if (!r.ok) {
    const msg = (j.error && j.error.message) || ("erreur " + r.status);
    if (r.status === 429) throw new Error(`Gemini : recherche Google refusée pour le modèle ${MODELE_RECHERCHE} — non incluse dans la formule gratuite (Gemini 3.x) ou quota épuisé. Activez la facturation Gemini. Détail : ${msg.slice(0, 160)}`);
    if (r.status === 404) throw new Error(`Gemini : modèle ${MODELE_RECHERCHE} introuvable. Indiquez un modèle valide dans GEMINI_MODEL_RECHERCHE sur Render.`);
    throw new Error("Gemini : " + msg);
  }
  const cand = (j.candidates || [])[0] || {};
  const texte = ((cand.content && cand.content.parts) || []).map(x => x.text || "").join("");
  const sources = (((cand.groundingMetadata || {}).groundingChunks) || []).map(c => c.web && { titre: c.web.title || "", url: c.web.uri || "" }).filter(Boolean);
  return { texte, sources };
}
// Liste d'entreprises trouvée par Gemini + Google Search. Résultats à vérifier : signalé à l'utilisateur.
async function rechercheGemini({ requete, ville, gouvernorat, portee, limite }) {
  const zone = portee === "gouvernorat" ? `gouvernorat de ${gouvernorat || ville}` : `${ville || gouvernorat}${gouvernorat && gouvernorat !== ville ? " (gouvernorat de " + gouvernorat + ")" : ""}`;
  const n = Math.max(5, Math.min(20, limite || 20));
  const prompt = `Recherche sur le web (Google) des établissements réels correspondant à « ${requete} » situés à ${zone}, en Tunisie.
Donne au maximum ${n} établissements différents, uniquement s'ils existent réellement et sont bien situés dans cette zone (pas dans une autre ville).
Pour chacun : nom exact, adresse (rue ou quartier si connue), ville, téléphone publié s'il est trouvé (sinon ""), source (site, page Facebook, annuaire, fiche Google).
N'invente jamais un établissement ni un numéro. Mieux vaut une liste courte et juste.
Réponds UNIQUEMENT par un tableau JSON, sans texte autour :
[{"nom":"","adresse":"","ville":"","telephone":"","source":""}]`;
  const { texte, sources } = await geminiRechercheWeb(prompt);
  const m = texte.match(/\[[\s\S]*\]/);
  let liste = [];
  if (m) { try { liste = JSON.parse(m[0]); } catch (e) { liste = []; } }
  const vus = new Set(), resultats = [];
  for (const x of Array.isArray(liste) ? liste : []) {
    const nom = String((x && x.nom) || "").trim().slice(0, 150);
    const cle = nom.toLowerCase().replace(/\s+/g, " ");
    if (!nom || vus.has(cle)) continue;
    vus.add(cle);
    resultats.push({ placeId: "", nom, adresse: String(x.adresse || "").trim().slice(0, 200), ville: String(x.ville || "").trim().slice(0, 80),
      tel: telTunisien(x.telephone), siteWeb: "", note: null, nbAvis: null, lat: null, lng: null, statutGoogle: "",
      sourceIA: String(x.source || "").trim().slice(0, 150) || "IA" });
    if (resultats.length >= n) break;
  }
  const avertissement = !sources.length
    ? "Gemini n'a pas effectué de recherche web : liste peu fiable, vérifiez chaque entreprise."
    : "Liste trouvée par IA (Gemini + Google) : vérifiez chaque entreprise et chaque numéro avant de l'utiliser.";
  return { resultats, avertissement, sources: sources.length };
}
function ficheDepuisPlace(pl) {
  return {
    placeId: pl.id || "",
    nom: (pl.displayName && pl.displayName.text) || "",
    adresse: pl.formattedAddress || "",
    tel: pl.internationalPhoneNumber || pl.nationalPhoneNumber || "",
    siteWeb: pl.websiteUri || "",
    note: pl.rating ?? null,
    nbAvis: pl.userRatingCount ?? null,
    lat: pl.location ? pl.location.latitude : null,
    lng: pl.location ? pl.location.longitude : null,
    statutGoogle: pl.businessStatus || "",
  };
}
async function placeDetails(placeId, avecAvis) {
  const r = await fetch(`https://places.googleapis.com/v1/places/${encodeURIComponent(placeId)}?languageCode=fr`, {
    headers: { "X-Goog-Api-Key": GOOGLE_PLACES_API_KEY, "X-Goog-FieldMask": CHAMPS_PLACE + (avecAvis ? ",reviews" : "") },
  });
  const j = await r.json();
  if (!r.ok) throw new Error((j.error && j.error.message) || "Erreur Google Places (" + r.status + ")");
  return j;
}
function nettoyerTexte(v, max) { return String(v || "").replace(/[\u0000-\u001f]/g, " ").slice(0, max).trim(); }
async function rechercheGoogle(requete, zoneTexte, limite) {
  const r = await fetch("https://places.googleapis.com/v1/places:searchText", {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Goog-Api-Key": GOOGLE_PLACES_API_KEY, "X-Goog-FieldMask": CHAMPS_PLACE.split(",").map(c => "places." + c).join(",") },
    body: JSON.stringify({ textQuery: `${requete} ${zoneTexte} Tunisie`, languageCode: "fr", regionCode: "TN", pageSize: Math.min(20, limite) }),
  });
  const j = await r.json();
  if (!r.ok) throw new Error("Google Places : " + ((j.error && j.error.message) || r.status));
  return (j.places || []).map(ficheDepuisPlace);
}
// Recherche de prospects. Corps : { requete, ville?, gouvernorat?, moteur?: "auto"|"google"|"osm", osm?: filtres OSM du segment, limite? }
//  - auto   : Google Maps si la clé est configurée (et le plafond du jour non atteint), sinon OpenStreetMap ;
//  - google : Google uniquement (erreur claire si non configuré) ;
//  - osm    : OpenStreetMap uniquement (gratuit — Overpass par tags de segment, repli recherche texte).
app.post("/api/prospection/recherche", limiteurIP("recherche de prospects", 30), verifierAuthIA, async (req, res) => {
  try {
    const requete = nettoyerTexte(req.body && req.body.requete, 120);
    const ville = nettoyerTexte(req.body && req.body.ville, 80);
    const gouvernorat = nettoyerTexte(req.body && req.body.gouvernorat, 60);
    const limite = Math.max(5, Math.min(60, parseInt(req.body && req.body.limite, 10) || 20));
    const moteur = ["auto", "google", "osm", "gemini"].includes(req.body && req.body.moteur) ? req.body.moteur : "auto";
    if (!requete || (!ville && !gouvernorat)) return res.status(400).json({ ok: false, message: "Requête et zone (ville ou gouvernorat) obligatoires." });
    const zoneTexte = [...new Set([ville, gouvernorat].filter(Boolean))].join(" ");
    let avertissement = "";
    if (moteur === "gemini") {
      if (!GEMINI_API_KEY) return res.status(400).json({ ok: false, message: "GEMINI_API_KEY non configurée côté serveur." });
      if (!consommerQuota("rechia")) return res.status(429).json({ ok: false, message: `Plafond journalier de recherches IA atteint (${PLAFONDS_JOUR.rechia}). Réessayez demain ou utilisez OpenStreetMap.` });
      const g = await rechercheGemini({ requete, ville, gouvernorat, portee: (req.body && req.body.portee) === "gouvernorat" ? "gouvernorat" : "ville", limite });
      return res.json({ ok: true, source: "Google via Gemini (IA)", moteurUtilise: "gemini", avertissement: g.avertissement, resultats: g.resultats });
    }
    if (moteur === "google" && !GOOGLE_PLACES_API_KEY) {
      return res.status(400).json({ ok: false, message: "Google Places n'est pas configuré sur le serveur (variable GOOGLE_PLACES_API_KEY). Choisissez OpenStreetMap ou ajoutez la clé (Paramètres → Prospection → guide Google Places)." });
    }
    if (GOOGLE_PLACES_API_KEY && moteur !== "osm") {
      if (!consommerQuota("places")) {
        const msg = `Plafond journalier de recherches Google atteint (${PLAFONDS_JOUR.places}).`;
        if (moteur === "google") return res.status(429).json({ ok: false, message: msg + " Réessayez demain." });
        avertissement = msg + " Résultats OpenStreetMap à la place.";
      } else {
        try {
          const resultats = await rechercheGoogle(requete, zoneTexte, limite);
          return res.json({ ok: true, source: "Google Maps", moteurUtilise: "google", resultats });
        } catch (err) {
          if (moteur === "google") return res.status(502).json({ ok: false, message: err.message });
          avertissement = err.message + " — résultats OpenStreetMap à la place.";
        }
      }
    }
    const portee = (req.body && req.body.portee) === "gouvernorat" ? "gouvernorat" : "ville";
    const o = await rechercheOSM({ requete, ville, gouvernorat, portee, osm: req.body && req.body.osm, limite });
    res.json({ ok: true, source: "OpenStreetMap", moteurUtilise: "osm", methodeOsm: o.methode, zoneUtilisee: o.zoneUtilisee || "", notes: o.notes, avertissement, resultats: o.resultats });
  } catch (err) {
    console.error("Erreur /api/prospection/recherche :", err);
    res.status(500).json({ ok: false, message: "Erreur de recherche : " + err.message });
  }
});
app.post("/api/prospection/details", limiteurIP("mise à jour de fiches", 150), verifierAuthIA, quotaJour("places"), async (req, res) => {
  try {
    if (!GOOGLE_PLACES_API_KEY) return res.status(400).json({ ok: false, message: "GOOGLE_PLACES_API_KEY non configurée sur le serveur : la mise à jour des fiches nécessite Google Places." });
    const placeId = String((req.body && req.body.placeId) || "");
    if (!placeId) return res.status(400).json({ ok: false, message: "placeId manquant." });
    res.json({ ok: true, fiche: ficheDepuisPlace(await placeDetails(placeId, false)) });
  } catch (err) {
    res.status(502).json({ ok: false, message: err.message });
  }
});
const schemaProspect = {
  type: Type.OBJECT,
  properties: {
    besoins: { type: Type.OBJECT, properties: { cameras: { type: Type.BOOLEAN }, alarme: { type: Type.BOOLEAN }, controleAcces: { type: Type.BOOLEAN }, reseau: { type: Type.BOOLEAN } } },
    priorite: { type: Type.STRING, description: "A, B ou C" },
    score: { type: Type.NUMBER, description: "0 à 100 : probabilité de signer" },
    pack: { type: Type.STRING, description: "Solution à proposer, 1 à 2 phrases" },
    argument: { type: Type.STRING, description: "Argument principal, 1 phrase" },
    signaux: { type: Type.STRING, description: "Indices concrets relevés (avis, horaires, activité), vide si aucun" },
    questions: { type: Type.ARRAY, items: { type: Type.STRING }, description: "3 questions à poser lors de la visite" },
    message: { type: Type.STRING, description: "Premier message WhatsApp, vouvoiement, 600 caractères maximum" },
  },
  required: ["besoins", "priorite", "score", "pack", "argument", "message"],
};
app.post("/api/prospection/analyse", limiteurIP("analyse de prospect", 30), verifierAuthIA, quotaJour("gemini"), async (req, res) => {
  try {
    if (!GEMINI_API_KEY) return res.status(500).json({ ok: false, message: "GEMINI_API_KEY non configurée côté serveur." });
    const { prospect = {}, entreprise = {}, offre = {} } = req.body || {};
    let avis = [];
    if (prospect.placeId && GOOGLE_PLACES_API_KEY && consommerQuota("places")) {
      try {
        const d = await placeDetails(prospect.placeId, true);
        avis = (d.reviews || []).slice(0, 5).map(r => (r.text && r.text.text) || (r.originalText && r.originalText.text) || "").filter(Boolean).map(t => t.slice(0, 500));
      } catch (e) { /* avis facultatifs */ }
    }
    const prompt = `Tu es le commercial de ${entreprise.nom || "SETCOM"}, installateur tunisien en sécurité électronique basé à ${entreprise.ville || "Jemmal"} (activités : ${entreprise.activites || "vidéosurveillance, alarme, contrôle d'accès, réseau"}).
Analyse ce prospect et remplis le schéma JSON.
Prospect : ${JSON.stringify({ nom: prospect.nom, segment: prospect.segment, adresse: prospect.adresse, ville: prospect.ville, noteGoogle: prospect.note, nombreAvis: prospect.nbAvis, siteWeb: prospect.siteWeb, notesCommercial: prospect.notes })}
Offre type du segment : ${JSON.stringify(offre)}
${avis.length ? "Extraits d'avis Google (repère les indices utiles : sécurité, vols, Wi-Fi, accès, horaires de nuit…) :\n- " + avis.join("\n- ") : "Aucun avis disponible."}
Règles :
- N'invente aucun fait sur le prospect : si tu n'as pas d'indice, raisonne à partir du segment et dis-le dans "signaux" (ou laisse vide).
- Priorité A = petite structure où le patron décide vite ou risque élevé (nuit, espèces, objets de valeur) ; C = grande chaîne dont les fournisseurs sont imposés par le siège.
- Le message est court, poli (vouvoiement), en français, propose un diagnostic sécurité gratuit sur place, sans prix sauf si l'offre en donne un, et se termine par une question.
- Si un avis évoque un problème (Wi-Fi faible, vols, portes, sécurité), appuie-toi dessus avec tact sans citer l'avis mot pour mot.`;
    const response = await ai.models.generateContent({
      model: MODELE,
      contents: [{ text: prompt }],
      config: { temperature: 0.4, responseMimeType: "application/json", responseSchema: schemaProspect },
    });
    const analyse = JSON.parse(response.text);
    if (analyse.message) analyse.message = String(analyse.message).slice(0, 900);
    res.json({ ok: true, analyse, avisUtilises: avis.length });
  } catch (err) {
    console.error("Erreur /api/prospection/analyse :", err);
    res.status(500).json({ ok: false, message: "Échec de l'analyse IA : " + (err && err.message ? err.message : "erreur inconnue") });
  }
});

// ---------- Téléphone d'un prospect par Gemini + recherche Google (gratuit dans le quota Gemini, sans carte) ----------
// Appel REST direct (indépendant de la version du SDK). Le numéro proposé DOIT être vérifié par l'utilisateur :
// l'application ne l'enregistre qu'après confirmation.
function telTunisien(v) {
  let d = String(v || "").replace(/\D/g, "");
  if (d.startsWith("00216")) d = d.slice(5); else if (d.startsWith("216") && d.length === 11) d = d.slice(3);
  if (d.length !== 8 || /^[01]/.test(d)) return "";
  return "+216 " + d.slice(0, 2) + " " + d.slice(2, 5) + " " + d.slice(5);
}
app.post("/api/prospection/telephone", limiteurIP("recherche de téléphone", 30), verifierAuthIA, quotaJour("telia"), async (req, res) => {
  try {
    if (!GEMINI_API_KEY) return res.status(500).json({ ok: false, message: "GEMINI_API_KEY non configurée côté serveur." });
    const b = req.body || {};
    const nom = String(b.nom || "").trim().slice(0, 150);
    if (!nom) return res.status(400).json({ ok: false, message: "Nom du prospect manquant." });
    const lieu = [b.adresse, b.ville, b.gouvernorat].map(x => String(x || "").trim()).filter(Boolean).join(", ").slice(0, 200) || "Tunisie";
    const prompt = `Recherche sur le web le numéro de téléphone de cet établissement en Tunisie.
Établissement : ${nom}
Lieu : ${lieu}
Règles strictes :
- Ne donne un numéro que s'il est publié dans une source trouvée (fiche Google, site officiel, page Facebook, annuaire) ET que cette source correspond bien à cet établissement et à ce lieu.
- N'invente jamais un numéro. En cas de doute ou d'homonyme dans une autre ville, réponds avec "telephone": "".
Réponds UNIQUEMENT par un objet JSON, sans texte autour :
{"telephone":"","autres":[],"source":"nom du site ou de la page","confiance":"haute|moyenne|faible","remarque":"1 phrase"}`;
    const w = await geminiRechercheWeb(prompt);
    const texte = w.texte;
    const sources = w.sources.slice(0, 5);
    let d = {};
    const m = texte.match(/\{[\s\S]*\}/);
    if (m) { try { d = JSON.parse(m[0]); } catch (e) { d = {}; } }
    const telephone = telTunisien(d.telephone);
    const autres = [...new Set((Array.isArray(d.autres) ? d.autres : []).map(telTunisien).filter(t => t && t !== telephone))].slice(0, 3);
    let confiance = ["haute", "moyenne", "faible"].includes(d.confiance) ? d.confiance : "faible";
    if (!sources.length) confiance = "faible"; // aucune recherche web réellement effectuée
    res.json({ ok: true, telephone, autres, source: String(d.source || "").slice(0, 150), confiance,
      remarque: String(d.remarque || "").slice(0, 300), sources, rechercheWeb: sources.length > 0 });
  } catch (err) {
    console.error("Erreur /api/prospection/telephone :", err);
    res.status(/^Gemini/.test(err && err.message) ? 502 : 500).json({ ok: false, message: "Échec de la recherche du téléphone : " + (err && err.message ? err.message : "erreur inconnue") });
  }
});

// ---------- Envoi d'un document client par e-mail (07/10) ----------
// SMTP gratuit : Gmail avec un « mot de passe d'application » (compte Google avec validation en 2 étapes).
// Variables Render : SMTP_USER (adresse Gmail), SMTP_PASS (mot de passe d'application, 16 lettres),
// facultatives : SMTP_HOST (smtp.gmail.com), SMTP_PORT (465), SMTP_NOM (nom affiché), SMTP_REPONSE (Reply-To).
// Non configuré → 501 : l'application ouvre alors le menu de partage à la place.
let transporteurMail = null;
async function obtenirTransporteurMail() {
  if (transporteurMail) return transporteurMail;
  const { default: nodemailer } = await import("nodemailer");
  const port = parseInt(process.env.SMTP_PORT || "465", 10);
  transporteurMail = nodemailer.createTransport({ host: process.env.SMTP_HOST || "smtp.gmail.com", port, secure: port === 465,
    auth: { user: process.env.SMTP_USER, pass: String(process.env.SMTP_PASS || "").replace(/\s+/g, "") } });
  return transporteurMail;
}
app.post("/api/email/envoyer", limiteurIP("envoi d'e-mails", 60), verifierAuthIA, async (req, res) => {
  try {
    if (!process.env.SMTP_USER || !process.env.SMTP_PASS) return res.status(501).json({ ok: false, message: "Envoi d'e-mails non configuré sur le serveur (SMTP_USER / SMTP_PASS)." });
    const b = req.body || {};
    const a = String(b.a || "").trim();
    if (!/^[^\s@,;]+@[^\s@,;]+\.[^\s@,;]+$/.test(a)) return res.status(400).json({ ok: false, message: "Adresse e-mail du client invalide." });
    const pdf = String(b.pdfBase64 || "");
    if (!pdf || pdf.length > 11 * 1024 * 1024) return res.status(400).json({ ok: false, message: "PDF manquant ou trop volumineux (8 Mo max)." });
    if (!consommerQuota("email")) return res.status(429).json({ ok: false, message: `Plafond journalier d'e-mails atteint (${PLAFONDS_JOUR.email}).` });
    const nomFichier = (String(b.nomFichier || "document.pdf").replace(/[^\w.\-]/g, "_").slice(0, 80) || "document.pdf").replace(/(\.pdf)?$/i, ".pdf");
    const t = await obtenirTransporteurMail();
    const info = await t.sendMail({
      from: process.env.SMTP_NOM ? `"${String(process.env.SMTP_NOM).replace(/"/g, "")}" <${process.env.SMTP_USER}>` : process.env.SMTP_USER,
      to: a, replyTo: process.env.SMTP_REPONSE || undefined,
      subject: String(b.sujet || "Document").slice(0, 200),
      text: String(b.texte || "").slice(0, 5000),
      attachments: [{ filename: nomFichier, content: Buffer.from(pdf, "base64"), contentType: "application/pdf" }],
    });
    res.json({ ok: true, id: info.messageId || "" });
  } catch (err) {
    console.error("Erreur /api/email/envoyer :", err);
    const m = err && err.code === "EAUTH" ? "Gmail refuse la connexion : vérifiez SMTP_USER et le mot de passe d'application (SMTP_PASS)." : "serveur de messagerie indisponible (détail dans les journaux Render)";
    res.status(502).json({ ok: false, message: "Échec de l'envoi : " + m });
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`GestComPro — backend IA démarré sur le port ${PORT} (modèle : ${MODELE})`);
});
