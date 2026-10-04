import express from "express";
import multer from "multer";
import cors from "cors";
import { GoogleGenAI, Type } from "@google/genai";
import "dotenv/config";

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
// voir netlify.toml), le navigateur peut bloquer ses propres appels fetch() vers CE serveur si les
// réponses ne portent pas explicitement cet en-tête, même quand CORS est déjà correctement
// configuré ci-dessus. Sans lui : risque réel que /api/capture, /api/ttn/* et /api/prospection cessent de
// répondre au frontend dès que l'isolation est activée côté navigateur — jamais vérifié en
// conditions réelles (pas de navigateur disponible ici), ajouté par précaution plutôt que découvert
// après coup.
app.use((req, res, next) => { res.setHeader("Cross-Origin-Resource-Policy", "cross-origin"); next(); });
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
};
const compteursJour = { date: "", gemini: 0, places: 0 };
function consommerQuota(type) {
  const jour = new Date().toISOString().slice(0, 10);
  if (compteursJour.date !== jour) { compteursJour.date = jour; compteursJour.gemini = 0; compteursJour.places = 0; }
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
    next();
  };
}
app.use("/api", limiterDebit(30)); // 30 requêtes/minute/IP sur toutes les routes — ajustable si besoin

const GEMINI_API_KEY = process.env.GEMINI_API_KEY || "";
const MODELE = process.env.GEMINI_MODEL || "gemini-2.5-flash";
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

// Point de contrôle simple pour vérifier que le serveur tourne et que la clé est bien chargée
// (sans jamais révéler la clé elle-même) — utile pour diagnostiquer un déploiement.
app.get("/api/health", (req, res) => {
  res.json({ ok: true, modele: MODELE, cleConfiguree: !!GEMINI_API_KEY, ttnConfigure: !!(EL_FATOORA_ENDPOINT && SIGNATURE_ENDPOINT),
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
function verifierAuthApplicative(req, res, next) {
  const cle = req.header("X-App-Api-Key");
  if (!APP_API_KEY || cle !== APP_API_KEY) return res.status(401).json({ ok: false, message: "Non autorisé (X-App-Api-Key manquante ou incorrecte)." });
  next();
}
// Authentification dédiée à l'Analyse IA — volontairement séparée de verifierAuthApplicative
// (TTN) : en-tête distinct, clé distincte, aucune des deux fonctions ne se lit ni ne s'utilise.
function verifierAuthIA(req, res, next) {
  const cle = req.header("X-Ia-Api-Key");
  if (!IA_API_KEY || cle !== IA_API_KEY) return res.status(401).json({ ok: false, message: "Non autorisé (X-Ia-Api-Key manquante ou incorrecte)." });
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

async function appelerOverpass(requete, fetchImpl = fetch, serveurs = OVERPASS) {
  let derniereErreur = null;
  for (const url of serveurs) {
    try {
      const r = await fetchAvecDelai(fetchImpl, url, {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded", "User-Agent": USER_AGENT },
        body: "data=" + encodeURIComponent(requete),
      }, 35000);
      if (r.status === 429 || r.status >= 500) { derniereErreur = new Error("Overpass " + r.status); continue; }
      if (!r.ok) throw new Error("Overpass a répondu " + r.status);
      const j = await r.json();
      return Array.isArray(j.elements) ? j.elements : [];
    } catch (err) { derniereErreur = err; }
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
  const cles = `~"^(name|name:fr|name:en|int_name|alt_name|official_name)$"~"^${motif}$",i`;
  const q = `[out:json][timeout:20];(node["place"~"^(city|town|village|suburb|quarter|neighbourhood|hamlet|locality)$"][${cles}](${s},${w},${n},${e});relation["boundary"="administrative"][${cles}](${s},${w},${n},${e}););out tags center bb 20;`;
  const els = await appelerOverpass(q, fetchImpl, serveurs);
  const rels = els.filter((x) => x.type === "relation" && x.bounds);
  const lieux = els.filter((x) => x.type === "node" && x.tags && x.tags.place).sort((a, b) => (RANG_LIEU[a.tags.place] || 9) - (RANG_LIEU[b.tags.place] || 9));
  if (portee === "gouvernorat") {
    const r = rels.sort((a, b) => (Number(a.tags.admin_level) || 9) - (Number(b.tags.admin_level) || 9))[0];
    if (r) return { bbox: [r.bounds.minlat, r.bounds.minlon, r.bounds.maxlat, r.bounds.maxlon], nom, source: "Overpass" };
  }
  if (lieux.length) { const p = lieux[0]; return { lat: p.lat, lon: p.lon, rayon: RAYON_LIEU[p.tags.place] || 4000, nom, source: "Overpass" }; }
  const r = rels.sort((a, b) => (Number(b.tags.admin_level) || 0) - (Number(a.tags.admin_level) || 0))[0];
  if (r) return { bbox: [r.bounds.minlat, r.bounds.minlon, r.bounds.maxlat, r.bounds.maxlon], nom, source: "Overpass" };
  return null;
}
async function localiserParPhoton(zone, fetchImpl) {
  const [s, w, n, e] = BBOX_TUNISIE;
  const url = `${PHOTON}?q=${encodeURIComponent(zone + " Tunisie")}&limit=1&bbox=${w},${s},${e},${n}`;
  const r = await fetchAvecDelai(fetchImpl, url, { headers: { "User-Agent": USER_AGENT } }, 15000);
  if (!r.ok) throw new Error("Photon a répondu " + r.status);
  const j = await r.json();
  const f = j && Array.isArray(j.features) && j.features[0];
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
  const lignes = filtres.map((f) => f.valeurs.length
    ? `nwr["${f.cle}"~"^(${f.valeurs.join("|")})$"]["name"](${ou});`
    : `nwr["${f.cle}"]["name"](${ou});`);
  return `[out:json][timeout:25];(${lignes.join("")});out center tags ${Math.max(5, Math.min(200, limite))};`;
}
function ficheDepuisOverpass(el, villeParDefaut = "") {
  const t = el.tags || {};
  const rue = [t["addr:housenumber"], t["addr:street"]].filter(Boolean).join(" ");
  const adresse = [rue, t["addr:suburb"], t["addr:city"] || t["addr:town"] || t["addr:village"]].filter(Boolean).join(", ");
  const lat = el.lat ?? (el.center && el.center.lat) ?? null;
  const lon = el.lon ?? (el.center && el.center.lon) ?? null;
  return {
    placeId: "", osmId: el.type && el.id ? `${el.type}/${el.id}` : "",
    nom: t["name:fr"] || t.name || "",
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
async function rechercheTextePhoton({ requete, zoneTexte, zone, limite }, fetchImpl) {
  const [s, w, n, e] = zone && zone.bbox ? zone.bbox : BBOX_TUNISIE;
  const centre = zone && zone.lat ? `&lat=${zone.lat}&lon=${zone.lon}` : "";
  const url = `${PHOTON}?q=${encodeURIComponent(requete + " " + zoneTexte)}&limit=${Math.min(40, limite)}&bbox=${w},${s},${e},${n}${centre}`;
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
    };
  }).filter((x) => x.nom);
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
// Point d'entrée. Ne lève jamais d'erreur : en cas de panne générale, renvoie 0 résultat et des notes.
async function rechercheOSM({ requete, ville, gouvernorat, portee, osm, limite = 40 }, fetchImpl = fetch, options = {}) {
  const filtres = filtresValides(osm);
  const notes = [];
  const zoneTexte = [...new Set([ville, gouvernorat].filter(Boolean))].join(" ");
  const loc = await localiserZone({ ville, gouvernorat, portee }, fetchImpl, options);
  const zone = loc.zone;
  if (!zone) notes.push("zone introuvable sur OpenStreetMap (" + (loc.notes.join(" ; ") || "aucune correspondance") + ")");
  if (filtres.length && zone) {
    try {
      const els = await appelerOverpass(construireRequeteOverpass(zone, filtres, limite), fetchImpl, options.serveursOverpass || OVERPASS);
      const fiches = dedoublonner(els.map((e) => ficheDepuisOverpass(e, ville || gouvernorat)).filter((f) => f.nom));
      if (fiches.length) return { resultats: fiches.slice(0, limite), methode: "overpass", notes };
      notes.push("aucun établissement de ce type référencé dans la zone");
    } catch (err) { notes.push("Overpass : " + err.message); }
  }
  for (const [nomService, f] of [["Photon", () => rechercheTextePhoton({ requete, zoneTexte, zone, limite }, fetchImpl)],
                                 ["Nominatim", () => rechercheTexteNominatim({ requete, zoneTexte, limite }, fetchImpl, options.delaiNominatim)]]) {
    try {
      const res = dedoublonner(await f());
      if (res.length) return { resultats: res.slice(0, limite), methode: "texte", notes };
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
    const moteur = ["auto", "google", "osm"].includes(req.body && req.body.moteur) ? req.body.moteur : "auto";
    if (!requete || (!ville && !gouvernorat)) return res.status(400).json({ ok: false, message: "Requête et zone (ville ou gouvernorat) obligatoires." });
    const zoneTexte = [...new Set([ville, gouvernorat].filter(Boolean))].join(" ");
    let avertissement = "";
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
    res.json({ ok: true, source: "OpenStreetMap", moteurUtilise: "osm", methodeOsm: o.methode, notes: o.notes, avertissement, resultats: o.resultats });
  } catch (err) {
    console.error("Erreur /api/prospection/recherche :", err);
    res.status(500).json({ ok: false, message: "Erreur de recherche : " + err.message });
  }
});
// Test de configuration depuis Paramètres → Prospection. Google : requête « identifiants seuls »
// (Text Search Essentials, sans coût) ; OpenStreetMap : géocodage de Monastir + requête Overpass minimale.
app.post("/api/prospection/test", limiteurIP("test de prospection", 20), verifierAuthIA, async (req, res) => {
  const resultat = { ok: true, google: { configure: !!GOOGLE_PLACES_API_KEY, ok: false, message: "" }, osm: { ok: false, message: "" }, quotasDuJour: { date: compteursJour.date, places: `${compteursJour.places}/${PLAFONDS_JOUR.places}` } };
  if (GOOGLE_PLACES_API_KEY) {
    try {
      const r = await fetch("https://places.googleapis.com/v1/places:searchText", {
        method: "POST", headers: { "Content-Type": "application/json", "X-Goog-Api-Key": GOOGLE_PLACES_API_KEY, "X-Goog-FieldMask": "places.id" },
        body: JSON.stringify({ textQuery: "pharmacie Monastir Tunisie", languageCode: "fr", regionCode: "TN", pageSize: 1 }),
      });
      const j = await r.json();
      resultat.google.ok = r.ok;
      resultat.google.message = r.ok ? "Clé valide, Places API (New) active." : ((j.error && j.error.message) || ("Erreur " + r.status));
    } catch (err) { resultat.google.message = err.message; }
  } else resultat.google.message = "Aucune clé GOOGLE_PLACES_API_KEY sur le serveur.";
  const services = [
    ["Overpass (catégories)", () => appelerOverpass('[out:json][timeout:15];node["amenity"="pharmacy"](35.70,10.75,35.80,10.85);out 1;')],
    ["Photon (localisation, recherche texte)", async () => { const z = await localiserParPhoton("Monastir", fetch); if (!z) throw new Error("aucune réponse"); }],
    ["Nominatim (secours)", async () => { const z = await localiserParNominatim("Monastir", fetch); if (!z) throw new Error("aucune réponse"); }],
  ];
  resultat.osm.details = [];
  for (const [nom, f] of services) {
    try { await f(); resultat.osm.details.push({ nom, ok: true, message: "répond" }); }
    catch (err) { resultat.osm.details.push({ nom, ok: false, message: err.message }); }
  }
  resultat.osm.ok = resultat.osm.details[0].ok && (resultat.osm.details[1].ok || resultat.osm.details[2].ok);
  resultat.osm.message = resultat.osm.ok ? "Overpass et un géocodeur répondent." : "Recherche OpenStreetMap indisponible depuis le serveur : " + resultat.osm.details.filter(d => !d.ok).map(d => d.nom + " — " + d.message).join(" ; ");
  res.json(resultat);
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

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`GestComPro — backend IA démarré sur le port ${PORT} (modèle : ${MODELE})`);
});
