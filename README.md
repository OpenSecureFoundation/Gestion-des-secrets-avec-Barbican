# Gestion des secrets avec Barbican
Projet de gestion des secrets avec OpenStack Barbican

# Objectifs:

• Développer une solution d’intégration de Barbican avec des applications tierces pour la gestion sécurisée des clés API

• Automatiser le renouvellement des certificats SSL/TLS stockés dans Barbican

# BarbiLink — Gestion des secrets avec OpenStack Barbican

## Description

BarbiLink est une application web Django permettant à des équipes de développement de gérer leurs secrets (clés API, certificats SSL/TLS, paires de clés RSA) de façon centralisée et sécurisée. Les secrets sont chiffrés et stockés dans OpenStack Barbican, un service de gestion de secrets dédié. L'authentification des utilisateurs et l'isolation des ressources par projet reposent sur OpenStack Keystone.

L'application fournit également une API REST permettant à des applications tierces de récupérer leurs secrets à la demande, sans les stocker dans leur propre code ou configuration.

---

## Architecture

```
Navigateur / Application tierce
        |
        v
  [ BarbiLink — Django 6 ]
        |
        |── Authentification ──► OpenStack Keystone
        |
        └── Stockage secrets ──► OpenStack Barbican
```

**Composants principaux :**

| Composant | Rôle |
|-----------|------|
| `accounts` | Gestion des comptes utilisateurs (inscription, connexion, profil, photo) |
| `apps_manager` | Gestion des applications et de leurs projets Keystone associés |
| `secrets_manager` | Création, renouvellement et suppression des secrets dans Barbican |
| `api_manager` | API REST publique (lecture de secrets par Bearer token) + notifications email |

---

## Fonctionnalites

- Creation et gestion d'applications (chaque application correspond a un projet Keystone isole)
- Ajout de secrets dans trois formats : generique (cle API, mot de passe), certificat SSL/TLS, paire de cles RSA
- Renouvellement manuel des secrets avec archivage de l'ancienne version dans Barbican
- Generation de jetons d'acces Bearer par secret pour les applications tierces
- API REST en lecture seule : `GET /api/v1/secrets/<nom>/`
- Notifications email non bloquantes pour chaque action (creation, modification, suppression, acces API)
- Deconnexion automatique apres 3 minutes d'inactivite
- Interface responsive avec barre de recherche globale et pagination
- Dashboard avec statistiques (nombre d'applications, secrets, certificats)

---

## Prerequis

- Python 3.12
- OpenStack Keystone (endpoint accessible en reseau)
- OpenStack Barbican (endpoint accessible en reseau)
- Compte Gmail avec mot de passe d'application (pour les notifications email)
- Git

---

## Installation

### 1. Cloner le depot

```bash
git clone https://github.com/OpenSecureFoundation/Gestion-des-secrets-avec-Barbican.git
cd Gestion-des-secrets-avec-Barbican
```

### 2. Creer et activer l'environnement virtuel

```bash
python3.12 -m venv env
source env/bin/activate
```

### 3. Installer les dependances

```bash
pip install -r requirements.txt
```

### 4. Configurer les variables d'environnement

Copier le fichier d'exemple et renseigner les valeurs :

```bash
cp .env.example .env
```

Editer `.env` :

```env
# Cle secrete Django (generer avec : python -c "import secrets; print(secrets.token_hex(50))")
SECRET_KEY=votre_cle_secrete_django

# OpenStack Keystone
KEYSTONE_URL=http://<ip-keystone>:5000/v3/
KEYSTONE_ADMIN_USERNAME=admin
KEYSTONE_ADMIN_PASSWORD=mot_de_passe_admin
KEYSTONE_ADMIN_PROJECT_ID=id_du_projet_admin
KEYSTONE_DOMAIN_ID=default

# OpenStack Barbican
BARBICAN_URL=http://<ip-barbican>:9311/v1/

# Email (Gmail)
EMAIL_HOST_USER=votre.adresse@gmail.com
EMAIL_HOST_PASSWORD=mot_de_passe_application_gmail
DEFAULT_FROM_EMAIL=BarbiLink <votre.adresse@gmail.com>
```

### 5. Appliquer les migrations

```bash
python manage.py migrate
```

### 6. Creer un superutilisateur (optionnel)

```bash
python manage.py createsuperuser
```

### 7. Lancer le serveur de developpement

```bash
python manage.py runserver
```

L'application est accessible sur `http://127.0.0.1:8000/`.

---

## Structure du projet

```
Gestion-des-secrets-avec-Barbican/
|
|-- BarbiLink/               # Configuration principale Django (settings, urls, wsgi)
|-- apps/
|   |-- accounts/            # Authentification et gestion des comptes
|   |-- apps_manager/        # Gestion des applications et projets Keystone
|   |-- secrets_manager/     # Gestion des secrets Barbican
|   |-- api_manager/         # API REST et notifications email
|
|-- templates/               # Templates HTML (base.html, partials HTMX)
|-- static/                  # Fichiers statiques (CSS, JS, images)
|-- media/                   # Fichiers uploades (photos de profil)
|-- logs/                    # Fichiers de logs applicatifs
|-- requirements.txt         # Dependances Python
|-- API_DOCUMENTATION.md     # Documentation de l'API pour les developpeurs tiers
|-- manage.py
```

---

## Configuration avancee

### Logs

Les logs applicatifs sont ecrits dans `logs/secrets_manager.log`. Le niveau par defaut est `INFO`. Pour passer en mode debug, modifier dans `BarbiLink/settings.py` :

```python
'level': 'DEBUG',
```

### Fichiers statiques (production)

En production, executer :

```bash
python manage.py collectstatic
```

puis configurer votre serveur web (Nginx, Apache) pour servir le repertoire `staticfiles/`.

### Base de donnees

Le projet utilise SQLite par defaut (`db.sqlite3`). Pour passer a PostgreSQL, modifier `DATABASES` dans `settings.py` et ajouter `psycopg2` aux dependances.

---

## Utilisation

### Creer une application

1. Se connecter sur BarbiLink
2. Aller dans **Mes applications** > **Nouvelle application**
3. Renseigner le nom — un projet Keystone isole est cree automatiquement

### Ajouter un secret

1. Ouvrir une application
2. Cliquer sur **Ajouter un secret**
3. Choisir le type : generique, certificat SSL/TLS ou paire de cles RSA
4. Renseigner le nom et la valeur (ou uploader les fichiers)
5. Le secret est chiffre et stocke dans Barbican

### Generer un jeton d'acces pour une application tierce

1. Ouvrir le detail d'une application
2. Sur la carte du secret concerne, cliquer sur **Generer un jeton**
3. Copier le jeton affiche (il ne sera plus visible ensuite)
4. Transmettre ce jeton a l'application tierce via une variable d'environnement

---

## API REST

L'API permet a des applications tierces de recuperer leurs secrets sans acceder a l'interface web.

**Endpoint :**

```
GET /api/v1/secrets/<nom_secret>/
Authorization: Bearer <jeton>
```

**Exemple :**

```bash
curl -H "Authorization: Bearer <jeton>" \
  https://<domaine>/api/v1/secrets/ma-cle-api/
```

**Reponse :**

```json
{
  "nom": "ma-cle-api",
  "type": "generic",
  "valeur": "sk_live_...",
  "encodage": "text"
}
```

Pour la documentation complete de l'API (tous les types de secrets, gestion des erreurs, exemples en Python, JavaScript, PHP), consulter [API_DOCUMENTATION.md](API_DOCUMENTATION.md).

---

## Tests

```bash
python manage.py test apps.api_manager
```

Les tests couvrent :
- Le modele `TokenAcces` (generation et renouvellement)
- Les vues de generation et renouvellement de jetons
- L'endpoint API (authentification, acces, erreurs)
- Le service de notifications email

---

## Auteurs

Rachel ANABA NGOUMOU et Harvis FOTSEU Landry — Master 2 Securite Cloud, Saint-Jean Ingenieur.
