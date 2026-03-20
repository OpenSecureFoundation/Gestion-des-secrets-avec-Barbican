# BarbiLink — Documentation de l'API REST

> **Version :** v1
> **Base URL :** `https://<votre-domaine>/api/v1/`
> **Format :** JSON
> **Authentification :** Bearer Token

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Obtenir un jeton d'accès](#2-obtenir-un-jeton-daccès)
3. [Authentification](#3-authentification)
4. [Référence des endpoints](#4-référence-des-endpoints)
5. [Format des réponses](#5-format-des-réponses)
6. [Interpréter le champ `encodage`](#6-interpréter-le-champ-encodage)
7. [Exemples d'utilisation](#7-exemples-dutilisation)
   - [cURL](#71-curl)
   - [Python (requests)](#72-python-requests)
   - [JavaScript (fetch)](#73-javascript-fetch)
   - [Node.js (axios)](#74-nodejs-axios)
   - [PHP (cURL)](#75-php-curl)
8. [Gestion des erreurs](#8-gestion-des-erreurs)
9. [Cas d'usage avancés](#9-cas-dusage-avancés)
10. [Bonnes pratiques & sécurité](#10-bonnes-pratiques--sécurité)

---

## 1. Vue d'ensemble

**BarbiLink** est une plateforme de gestion de secrets sécurisée basée sur **OpenStack Barbican**. Son API REST permet à vos applications tierces de récupérer des secrets (clés API, certificats SSL/TLS, paires de clés RSA) de façon sécurisée, sans jamais stocker ces secrets dans votre propre code ou infrastructure.

### Principe de fonctionnement

```
Votre Application          BarbiLink API              OpenStack Barbican
      │                         │                            │
      │──── GET /api/v1/secrets/mon-secret/ ────►           │
      │     Authorization: Bearer <token>                    │
      │                         │                            │
      │                         │──── récupère payload ─────►
      │                         │◄─── payload chiffré ───────
      │◄─── { valeur: "..." } ──│
```

**Ce que BarbiLink garantit :**
- Les secrets ne transitent jamais en clair dans les logs de votre application
- Chaque secret a un jeton d'accès révocable indépendamment
- Chaque accès API déclenche une notification email au propriétaire du secret
- Les secrets sont stockés et chiffrés par Barbican (service dédié OpenStack)

---

## 2. Obtenir un jeton d'accès

Un **jeton d'accès** est nécessaire pour chaque secret auquel vous souhaitez accéder. Il est généré via l'interface web BarbiLink par le propriétaire du secret.

### Étapes pour le propriétaire du secret

1. Connectez-vous sur BarbiLink (`https://<votre-domaine>/`)
2. Naviguez vers **Mes applications** → sélectionnez votre application
3. Trouvez le secret concerné dans la liste
4. Cliquez sur **Générer un jeton** (ou **Renouveler le jeton** si un jeton existe déjà)
5. Copiez le jeton affiché — **il n'est affiché qu'une seule fois**
6. Transmettez ce jeton à votre application de façon sécurisée (variable d'environnement, secret manager, etc.)

### Caractéristiques du jeton

| Propriété | Valeur |
|-----------|--------|
| Format | Hexadécimal, 64 caractères |
| Longueur | 256 bits (32 octets) |
| Portée | **Un jeton = un secret** (pas d'accès croisé) |
| Expiration | Aucune (révocation manuelle uniquement) |
| Révocation | En cliquant sur "Renouveler le jeton" dans l'interface |

> **Important :** Renouveler un jeton invalide immédiatement l'ancien. Toutes les applications utilisant l'ancien jeton recevront une erreur `401` jusqu'à ce qu'elles soient mises à jour.

---

## 3. Authentification

Toutes les requêtes vers l'API doivent inclure le header HTTP suivant :

```
Authorization: Bearer <votre_jeton>
```

**Exemple :**
```
Authorization: Bearer a3f8d2c1b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1
```

L'API **ne supporte pas** :
- L'authentification par cookie de session
- L'authentification Basic (username/password)
- Les clés API dans les query parameters

---

## 4. Référence des endpoints

### `GET /api/v1/secrets/<nom_secret>/`

Récupère la valeur d'un secret stocké dans Barbican.

#### Paramètres

| Paramètre | Type | Emplacement | Obligatoire | Description |
|-----------|------|-------------|-------------|-------------|
| `nom_secret` | string | URL path | Oui | Nom exact du secret tel que défini dans BarbiLink |
| `type` | string | Query string | Non | Pour les secrets RSA uniquement : `public` (défaut) ou `private` |

#### Headers requis

| Header | Valeur |
|--------|--------|
| `Authorization` | `Bearer <jeton>` |

#### Exemples d'URL

```
GET /api/v1/secrets/ma-cle-api/
GET /api/v1/secrets/mon-certificat-ssl/
GET /api/v1/secrets/ma-paire-rsa/?type=public
GET /api/v1/secrets/ma-paire-rsa/?type=private
```

#### Réponses possibles

| Code HTTP | Signification |
|-----------|---------------|
| `200 OK` | Secret récupéré avec succès |
| `401 Unauthorized` | Header `Authorization` absent ou jeton invalide/révoqué |
| `403 Forbidden` | Le jeton est valide mais ne donne pas accès à ce secret |
| `405 Method Not Allowed` | Méthode HTTP autre que GET |
| `500 Internal Server Error` | Erreur lors de la lecture dans Barbican |
| `503 Service Unavailable` | Barbican temporairement indisponible |

---

## 5. Format des réponses

### Réponse de succès (200)

Toutes les réponses de succès partagent la même structure JSON :

```json
{
  "nom": "nom-du-secret",
  "type": "<type_du_secret>",
  "valeur": "<contenu_du_secret>",
  "encodage": "text | base64"
}
```

#### Champ `type` — valeurs possibles

| Valeur | Description |
|--------|-------------|
| `"generic"` | Secret générique (clé API, mot de passe, token, etc.) |
| `"certificate"` | Certificat SSL/TLS (format PEM) |
| `"rsa_public"` | Clé publique RSA (format PEM) |
| `"rsa_private"` | Clé privée RSA (format PEM) |

#### Exemples de réponses par type

**Secret générique (clé API) :**
```json
{
  "nom": "stripe-api-key",
  "type": "generic",
  "valeur": "sk_live_51Hx9zA2eZvKYlo2C...",
  "encodage": "text"
}
```

**Certificat SSL/TLS :**
```json
{
  "nom": "certificat-production",
  "type": "certificate",
  "valeur": "-----BEGIN CERTIFICATE-----\nMIIDXTCCAkWgAwIBAgIJAL...\n-----END CERTIFICATE-----",
  "encodage": "text"
}
```

**Clé publique RSA :**
```json
{
  "nom": "cles-rsa-app",
  "type": "rsa_public",
  "valeur": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0B...\n-----END PUBLIC KEY-----",
  "encodage": "text"
}
```

**Secret binaire (encodé en base64) :**
```json
{
  "nom": "secret-binaire",
  "type": "generic",
  "valeur": "U2VjcmV0QmluYWlyZQ==",
  "encodage": "base64"
}
```

### Réponse d'erreur

```json
{
  "erreur": "Description lisible de l'erreur."
}
```

---

## 6. Interpréter le champ `encodage`

Le champ `encodage` indique comment le champ `valeur` est représenté.

### `"encodage": "text"`

La valeur est une chaîne de caractères UTF-8 directement utilisable.

```python
# Python — utilisation directe
reponse = requests.get(url, headers=headers).json()
if reponse["encodage"] == "text":
    ma_cle = reponse["valeur"]          # Utilisation directe
```

### `"encodage": "base64"`

La valeur est encodée en Base64. Ce cas se produit lorsque le secret contient des données binaires (par exemple, un fichier de clé uploadé directement). Vous devez décoder avant utilisation.

```python
# Python — décodage base64
import base64

reponse = requests.get(url, headers=headers).json()
if reponse["encodage"] == "base64":
    donnees_binaires = base64.b64decode(reponse["valeur"])
```

```javascript
// JavaScript — décodage base64
const reponse = await fetch(url, { headers }).then(r => r.json());
if (reponse.encodage === "base64") {
  const binaryString = atob(reponse.valeur);
  const bytes = new Uint8Array([...binaryString].map(c => c.charCodeAt(0)));
}
```

### Règle pratique : toujours vérifier `encodage`

```python
def extraire_valeur(reponse):
    """Retourne la valeur brute quelle que soit l'encodage."""
    import base64
    if reponse.get("encodage") == "base64":
        return base64.b64decode(reponse["valeur"])
    return reponse["valeur"]
```

---

## 7. Exemples d'utilisation

### 7.1 cURL

#### Secret générique (clé API)

```bash
curl -s \
  -H "Authorization: Bearer a3f8d2c1b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1" \
  https://<votre-domaine>/api/v1/secrets/stripe-api-key/
```

**Réponse :**
```json
{
  "nom": "stripe-api-key",
  "type": "generic",
  "valeur": "sk_live_51Hx9zA...",
  "encodage": "text"
}
```

#### Extraire uniquement la valeur avec jq

```bash
TOKEN="a3f8d2c1b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"
SECRET_NAME="stripe-api-key"

VALEUR=$(curl -s \
  -H "Authorization: Bearer $TOKEN" \
  https://<votre-domaine>/api/v1/secrets/$SECRET_NAME/ \
  | jq -r '.valeur')

echo "Clé récupérée : $VALEUR"
```

#### Certificat SSL — sauvegarder dans un fichier

```bash
curl -s \
  -H "Authorization: Bearer $TOKEN" \
  https://<votre-domaine>/api/v1/secrets/certificat-production/ \
  | jq -r '.valeur' > /etc/ssl/certs/mon-cert.pem
```

#### Paire de clés RSA — clé publique

```bash
curl -s \
  -H "Authorization: Bearer $TOKEN" \
  "https://<votre-domaine>/api/v1/secrets/cles-rsa-app/?type=public" \
  | jq -r '.valeur'
```

#### Paire de clés RSA — clé privée

```bash
curl -s \
  -H "Authorization: Bearer $TOKEN" \
  "https://<votre-domaine>/api/v1/secrets/cles-rsa-app/?type=private" \
  | jq -r '.valeur' > cle_privee.pem

chmod 600 cle_privee.pem
```

#### Vérifier le code de statut HTTP

```bash
HTTP_CODE=$(curl -o /dev/null -s -w "%{http_code}" \
  -H "Authorization: Bearer $TOKEN" \
  https://<votre-domaine>/api/v1/secrets/mon-secret/)

if [ "$HTTP_CODE" = "200" ]; then
  echo "Succès"
elif [ "$HTTP_CODE" = "401" ]; then
  echo "Jeton invalide ou manquant"
elif [ "$HTTP_CODE" = "403" ]; then
  echo "Accès refusé à ce secret"
elif [ "$HTTP_CODE" = "503" ]; then
  echo "Service temporairement indisponible"
fi
```

---

### 7.2 Python (requests)

#### Installation

```bash
pip install requests
```

#### Lecture d'un secret générique

```python
import requests
import base64

BARBILINK_URL = "https://<votre-domaine>/api/v1"
TOKEN = "a3f8d2c1b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1"

def get_secret(nom_secret, type_rsa=None):
    """
    Récupère un secret depuis BarbiLink.

    Args:
        nom_secret (str): Nom du secret tel que défini dans BarbiLink.
        type_rsa (str, optional): 'public' ou 'private' pour les secrets RSA.

    Returns:
        str | bytes: La valeur du secret (str si text, bytes si base64).

    Raises:
        ValueError: Si le jeton est invalide, révoqué ou non autorisé.
        RuntimeError: Si le service est indisponible.
    """
    url = f"{BARBILINK_URL}/secrets/{nom_secret}/"
    headers = {"Authorization": f"Bearer {TOKEN}"}
    params = {}

    if type_rsa:
        params["type"] = type_rsa

    response = requests.get(url, headers=headers, params=params, timeout=10)

    if response.status_code == 200:
        data = response.json()
        if data["encodage"] == "base64":
            return base64.b64decode(data["valeur"])
        return data["valeur"]

    elif response.status_code == 401:
        raise ValueError(f"Authentification échouée : {response.json().get('erreur')}")

    elif response.status_code == 403:
        raise ValueError(f"Accès refusé : {response.json().get('erreur')}")

    elif response.status_code == 503:
        raise RuntimeError("Service BarbiLink temporairement indisponible. Réessayez plus tard.")

    else:
        raise RuntimeError(f"Erreur inattendue ({response.status_code}) : {response.text}")


# --- Utilisation ---

# Clé API Stripe
cle_stripe = get_secret("stripe-api-key")
print(f"Clé Stripe : {cle_stripe}")

# Certificat SSL
certificat_pem = get_secret("certificat-production")
with open("/tmp/cert.pem", "w") as f:
    f.write(certificat_pem)

# Clé RSA publique
cle_publique = get_secret("cles-rsa-app", type_rsa="public")

# Clé RSA privée (données PEM, prêtes à l'emploi)
cle_privee = get_secret("cles-rsa-app", type_rsa="private")
```

#### Classe cliente complète avec retry et cache

```python
import requests
import base64
import time
import logging
from functools import lru_cache

logger = logging.getLogger(__name__)

class BarbiLinkClient:
    """
    Client officiel pour l'API BarbiLink.

    Usage:
        client = BarbiLinkClient(
            base_url="https://<votre-domaine>/api/v1",
            token="votre_jeton_64_chars"
        )
        cle = client.get_secret("ma-cle-api")
    """

    def __init__(self, base_url: str, token: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update({"Authorization": f"Bearer {token}"})

    def get_secret(self, nom: str, type_rsa: str = None) -> str | bytes:
        """
        Récupère un secret par son nom.

        Args:
            nom: Nom exact du secret dans BarbiLink.
            type_rsa: 'public' ou 'private' pour les conteneurs RSA.

        Returns:
            str pour les secrets texte, bytes pour les secrets binaires.
        """
        url = f"{self.base_url}/secrets/{nom}/"
        params = {"type": type_rsa} if type_rsa else {}

        try:
            resp = self._session.get(url, params=params, timeout=self.timeout)
        except requests.ConnectionError:
            raise RuntimeError("Impossible de joindre le serveur BarbiLink.")
        except requests.Timeout:
            raise RuntimeError("Le serveur BarbiLink n'a pas répondu dans le délai imparti.")

        return self._traiter_reponse(resp, nom)

    def get_secret_with_retry(self, nom: str, type_rsa: str = None,
                               max_retries: int = 3, delay: float = 2.0) -> str | bytes:
        """Récupère un secret avec retry automatique sur les erreurs 503."""
        for tentative in range(1, max_retries + 1):
            try:
                return self.get_secret(nom, type_rsa)
            except RuntimeError as e:
                if "indisponible" in str(e) and tentative < max_retries:
                    logger.warning("BarbiLink indisponible, tentative %d/%d dans %.0fs",
                                   tentative, max_retries, delay)
                    time.sleep(delay)
                    delay *= 2  # backoff exponentiel
                else:
                    raise

    def _traiter_reponse(self, resp: requests.Response, nom: str) -> str | bytes:
        if resp.status_code == 200:
            data = resp.json()
            if data.get("encodage") == "base64":
                return base64.b64decode(data["valeur"])
            return data["valeur"]

        try:
            message_erreur = resp.json().get("erreur", resp.text)
        except Exception:
            message_erreur = resp.text

        codes = {
            401: ValueError,
            403: PermissionError,
            503: RuntimeError,
            500: RuntimeError,
        }
        exc_class = codes.get(resp.status_code, RuntimeError)
        raise exc_class(f"[{resp.status_code}] {message_erreur}")
```

#### Utilisation avec les variables d'environnement (recommandé)

```python
import os
from dotenv import load_dotenv

load_dotenv()

client = BarbiLinkClient(
    base_url=os.environ["BARBILINK_URL"],
    token=os.environ["BARBILINK_TOKEN_MON_SECRET"],
)

cle = client.get_secret("mon-secret")
```

Fichier `.env` de votre application :
```env
BARBILINK_URL=https://<votre-domaine>/api/v1
BARBILINK_TOKEN_MON_SECRET=a3f8d2c1b4e5f6a7b8...
```

---

### 7.3 JavaScript (fetch)

#### Lecture d'un secret dans un navigateur ou Node.js (ES Modules)

```javascript
const BARBILINK_URL = "https://<votre-domaine>/api/v1";
const TOKEN = "a3f8d2c1b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1";

/**
 * Récupère un secret depuis BarbiLink.
 * @param {string} nomSecret - Nom du secret
 * @param {string|null} typeRsa - 'public' | 'private' (RSA uniquement)
 * @returns {Promise<string|Uint8Array>} La valeur du secret
 */
async function getSecret(nomSecret, typeRsa = null) {
  let url = `${BARBILINK_URL}/secrets/${nomSecret}/`;
  if (typeRsa) url += `?type=${typeRsa}`;

  const response = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${TOKEN}`,
    },
  });

  if (!response.ok) {
    const erreur = await response.json().catch(() => ({ erreur: response.statusText }));
    const messages = {
      401: `Authentification échouée : ${erreur.erreur}`,
      403: `Accès refusé : ${erreur.erreur}`,
      503: "Service BarbiLink temporairement indisponible.",
      500: "Erreur interne du serveur.",
    };
    throw new Error(messages[response.status] ?? `Erreur ${response.status} : ${erreur.erreur}`);
  }

  const data = await response.json();

  if (data.encodage === "base64") {
    // Décodage Base64 → Uint8Array
    const binaryString = atob(data.valeur);
    return new Uint8Array([...binaryString].map((c) => c.charCodeAt(0)));
  }

  return data.valeur;
}


// --- Utilisation ---

// Secret générique
try {
  const cleApi = await getSecret("stripe-api-key");
  console.log("Clé API :", cleApi);
} catch (err) {
  console.error("Erreur BarbiLink :", err.message);
}

// Clé RSA publique
const clePublique = await getSecret("cles-rsa-app", "public");

// Clé RSA privée
const clePrivee = await getSecret("cles-rsa-app", "private");
```

---

### 7.4 Node.js (axios)

#### Installation

```bash
npm install axios
```

#### Client BarbiLink pour Node.js

```javascript
const axios = require("axios");

const barbilink = axios.create({
  baseURL: process.env.BARBILINK_URL || "https://<votre-domaine>/api/v1",
  headers: {
    Authorization: `Bearer ${process.env.BARBILINK_TOKEN}`,
  },
  timeout: 10000,
});

/**
 * Récupère un secret depuis BarbiLink.
 * @param {string} nomSecret
 * @param {'public'|'private'|null} typeRsa
 */
async function getSecret(nomSecret, typeRsa = null) {
  const params = typeRsa ? { type: typeRsa } : {};

  try {
    const { data } = await barbilink.get(`/secrets/${nomSecret}/`, { params });

    if (data.encodage === "base64") {
      return Buffer.from(data.valeur, "base64");
    }
    return data.valeur;

  } catch (error) {
    if (error.response) {
      const { status, data } = error.response;
      const msg = data?.erreur ?? "Erreur inconnue";

      if (status === 401) throw new Error(`Jeton invalide : ${msg}`);
      if (status === 403) throw new Error(`Accès refusé : ${msg}`);
      if (status === 503) throw new Error("Service indisponible, réessayez plus tard.");
      throw new Error(`[${status}] ${msg}`);
    }
    if (error.code === "ECONNREFUSED") {
      throw new Error("Impossible de joindre le serveur BarbiLink.");
    }
    throw error;
  }
}

module.exports = { getSecret };


// --- Utilisation ---
(async () => {
  // Clé API
  const cleStripe = await getSecret("stripe-api-key");

  // Écriture de la clé privée RSA dans un fichier
  const clePrivee = await getSecret("cles-rsa-app", "private");
  require("fs").writeFileSync("./cle_privee.pem", clePrivee, { mode: 0o600 });

  console.log("Secrets chargés avec succès.");
})();
```

---

### 7.5 PHP (cURL)

```php
<?php

define('BARBILINK_URL', 'https://<votre-domaine>/api/v1');
define('BARBILINK_TOKEN', getenv('BARBILINK_TOKEN'));

/**
 * Récupère un secret depuis BarbiLink.
 *
 * @param string $nomSecret Nom du secret
 * @param string|null $typeRsa 'public' | 'private' pour les secrets RSA
 * @return string|array La valeur du secret (string si text, array sinon)
 * @throws RuntimeException En cas d'erreur d'accès ou de service
 */
function getSecret(string $nomSecret, ?string $typeRsa = null): string
{
    $url = BARBILINK_URL . '/secrets/' . urlencode($nomSecret) . '/';
    if ($typeRsa) {
        $url .= '?type=' . urlencode($typeRsa);
    }

    $ch = curl_init($url);
    curl_setopt_array($ch, [
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_HTTPHEADER     => ['Authorization: Bearer ' . BARBILINK_TOKEN],
        CURLOPT_TIMEOUT        => 10,
        CURLOPT_SSL_VERIFYPEER => true,
    ]);

    $body       = curl_exec($ch);
    $httpCode   = curl_getinfo($ch, CURLINFO_HTTP_CODE);
    $curlError  = curl_error($ch);
    curl_close($ch);

    if ($curlError) {
        throw new RuntimeException("Erreur cURL : " . $curlError);
    }

    $data = json_decode($body, true);

    if ($httpCode === 200) {
        if ($data['encodage'] === 'base64') {
            return base64_decode($data['valeur']);
        }
        return $data['valeur'];
    }

    $messages = [
        401 => 'Jeton d\'accès invalide ou révoqué.',
        403 => 'Ce jeton ne donne pas accès à ce secret.',
        503 => 'Service BarbiLink temporairement indisponible.',
        500 => 'Erreur interne du serveur BarbiLink.',
    ];

    throw new RuntimeException(
        $messages[$httpCode] ?? ("Erreur HTTP {$httpCode} : " . ($data['erreur'] ?? $body))
    );
}

// --- Utilisation ---
try {
    // Clé API
    $cleStripe = getSecret('stripe-api-key');

    // Clé RSA privée
    $clePrivee = getSecret('cles-rsa-app', 'private');
    file_put_contents('/tmp/cle_privee.pem', $clePrivee, LOCK_EX);
    chmod('/tmp/cle_privee.pem', 0600);

} catch (RuntimeException $e) {
    error_log('[BarbiLink] ' . $e->getMessage());
    // Gérer l'échec selon votre logique métier
}
?>
```

---

## 8. Gestion des erreurs

### Tableau récapitulatif

| Code HTTP | Corps JSON | Cause probable | Action recommandée |
|-----------|------------|----------------|-------------------|
| `200` | `{ nom, type, valeur, encodage }` | Succès | Utiliser `valeur` selon `encodage` |
| `401` | `{ "erreur": "Authentification requise..." }` | Header `Authorization` absent | Ajouter le header |
| `401` | `{ "erreur": "Jeton invalide ou révoqué..." }` | Jeton expiré/révoqué | Contacter le propriétaire pour un nouveau jeton |
| `403` | `{ "erreur": "Ce jeton ne vous autorise pas..." }` | Mauvais jeton pour ce secret | Vérifier que le jeton correspond bien à ce nom de secret |
| `405` | `{ "erreur": "Méthode non autorisée." }` | Méthode autre que GET | Utiliser uniquement GET |
| `500` | `{ "erreur": "Impossible de lire le secret." }` | Erreur Barbican côté serveur | Contacter l'administrateur BarbiLink |
| `503` | `{ "erreur": "Service temporairement indisponible." }` | Barbican hors ligne | Attendre et réessayer (backoff exponentiel) |

### Erreurs courantes et solutions

**Erreur 401 — "Authentification requise"**
```bash
# Problème : header Authorization absent
curl https://<votre-domaine>/api/v1/secrets/mon-secret/
# → 401

# Solution : toujours inclure le header Bearer
curl -H "Authorization: Bearer <token>" https://<votre-domaine>/api/v1/secrets/mon-secret/
```

**Erreur 401 — "Jeton invalide ou révoqué"**
- Le jeton a été renouvelé dans l'interface BarbiLink (l'ancien est automatiquement invalidé)
- Le jeton contient une faute de frappe
- **Action :** récupérer le nouveau jeton auprès du propriétaire du secret

**Erreur 403 — "Ce jeton ne vous autorise pas"**
- Vous utilisez le bon jeton, mais avec un mauvais nom de secret dans l'URL
- **Action :** vérifier que `<nom_secret>` dans l'URL correspond exactement au nom affiché dans BarbiLink (sensible à la casse)

**Erreur 503 — Service indisponible**
- OpenStack Barbican est temporairement hors ligne
- **Action :** implémenter un retry avec backoff exponentiel

```python
import time

def get_secret_resilient(client, nom, max_retries=3):
    for i in range(max_retries):
        try:
            return client.get_secret(nom)
        except RuntimeError as e:
            if "indisponible" in str(e) and i < max_retries - 1:
                time.sleep(2 ** i)  # 1s, 2s, 4s...
            else:
                raise
```

---

## 9. Cas d'usage avancés

### Chargement des secrets au démarrage de l'application

Pattern recommandé : charger tous les secrets en mémoire une seule fois au démarrage, ne plus appeler l'API ensuite.

```python
# config.py — Chargement des secrets au démarrage
import os
from barbilink_client import BarbiLinkClient

_client = BarbiLinkClient(
    base_url=os.environ["BARBILINK_URL"],
    token=os.environ["BARBILINK_TOKEN"],
)

class Secrets:
    """Singleton chargé une fois au démarrage."""
    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._charger()
        return cls._instance

    def _charger(self):
        self.stripe_key   = _client.get_secret("stripe-api-key")
        self.jwt_secret   = _client.get_secret("jwt-signing-key")
        self.smtp_password = _client.get_secret("gmail-smtp-password")
        self.tls_cert     = _client.get_secret("certificat-production")
        self.rsa_private  = _client.get_secret("cles-rsa-app", type_rsa="private")

# Dans votre application :
secrets = Secrets()
stripe.api_key = secrets.stripe_key
```

### Utilisation d'un certificat SSL récupéré depuis BarbiLink

```python
import ssl
import tempfile
import os

def creer_contexte_ssl(client, nom_cert, nom_cle):
    """Crée un contexte SSL depuis des secrets BarbiLink."""
    cert_pem = client.get_secret(nom_cert)
    cle_pem  = client.get_secret(nom_cle, type_rsa="private")

    # Écriture temporaire (nécessaire pour ssl.SSLContext)
    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f_cert:
        f_cert.write(cert_pem)
        cert_path = f_cert.name

    with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as f_key:
        f_key.write(cle_pem)
        key_path = f_key.name

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile=cert_path, keyfile=key_path)
    finally:
        os.unlink(cert_path)
        os.unlink(key_path)

    return ctx
```

### Vérification d'une signature JWT avec une clé RSA BarbiLink

```python
import jwt  # pip install PyJWT

def verifier_token_jwt(client, token_jwt, nom_secret_rsa):
    """Vérifie un JWT en récupérant la clé publique depuis BarbiLink."""
    cle_publique = client.get_secret(nom_secret_rsa, type_rsa="public")
    payload = jwt.decode(token_jwt, cle_publique, algorithms=["RS256"])
    return payload
```

---

## 10. Bonnes pratiques & sécurité

### Ne jamais coder le jeton en dur dans le code source

```python
# MAUVAIS — ne jamais faire cela
TOKEN = "a3f8d2c1b4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9..."

# BON — utiliser les variables d'environnement
import os
TOKEN = os.environ["BARBILINK_TOKEN"]
```

### Ajouter le jeton dans `.gitignore`

```
# .gitignore
.env
*.env
secrets.json
```

### Protéger les fichiers de clés privées

```bash
# Restreindre les permissions d'une clé privée
chmod 600 /chemin/vers/cle_privee.pem
chown monuser:monuser /chemin/vers/cle_privee.pem
```

### Ne pas logger les valeurs des secrets

```python
# MAUVAIS
cle = client.get_secret("ma-cle")
logging.info(f"Clé récupérée : {cle}")  # La clé apparaît dans les logs !

# BON
cle = client.get_secret("ma-cle")
logging.info("Secret 'ma-cle' chargé avec succès.")
```

### Gérer le renouvellement de jeton sans interruption de service

Lorsqu'un jeton est renouvelé dans BarbiLink, l'ancien jeton est immédiatement révoqué. Pour les applications critiques, procédez ainsi :

1. **Mettre à jour** la variable d'environnement avec le nouveau jeton
2. **Redémarrer** l'application (ou recharger la configuration à chaud)
3. **Vérifier** que l'application fonctionne avant de supprimer l'ancien jeton de vos systèmes

### Fréquence de renouvellement recommandée

| Type de secret | Fréquence de renouvellement du jeton |
|----------------|---------------------------------------|
| Clé API externe critique | Tous les 3 mois |
| Certificat SSL | Avant expiration du certificat |
| Clé RSA de signature | Tous les 6 mois |
| Secret de développement | Selon politique de l'équipe |

### Limiter la portée des jetons

Chaque jeton dans BarbiLink ne donne accès qu'à **un seul secret**. Si votre application a besoin de plusieurs secrets, vous aurez plusieurs jetons — c'est voulu. Cela limite l'impact en cas de compromission d'un jeton.

### Surveiller les notifications email

Chaque accès via l'API déclenche une notification email au propriétaire du secret. Si vous recevez des notifications inattendues, c'est un indicateur de compromission possible du jeton.

---

## Annexe — Checklist d'intégration

- [ ] Jeton stocké dans une variable d'environnement (pas dans le code)
- [ ] Fichier `.env` ajouté au `.gitignore`
- [ ] Gestion des erreurs 401, 403, 503 implémentée
- [ ] Retry avec backoff exponentiel pour les erreurs 503
- [ ] Les valeurs de secrets ne sont jamais loggées
- [ ] Les fichiers de clés ont les permissions Unix restreintes (`chmod 600`)
- [ ] Un jeton distinct par secret utilisé
- [ ] Procédure de renouvellement de jeton documentée en interne

---

*Documentation BarbiLink — Rachel & Harvis — Master 2 Sécurité Cloud*
