# BarbiLink — Elements de presentation PowerPoint
# Gestion des secrets avec OpenStack Barbican
### Rachel ANABA NGOUMOU & Harvis FOTSEU Landry — Master 2 Securite Cloud

---

## SLIDE 1 — Titre

**Titre principal :**
Gestion des secrets avec OpenStack Barbican

**Sous-titre :**
Conception et developpement d'une plateforme web de gestion centralisee des secrets cryptographiques

**Auteurs :** Rachel ANABA NGOUMOU & Harvis FOTSEU Landry
**Formation :** Master 2 Securite Cloud — Saint-Jean Ingenieur
**Annee :** 2025-2026

---

## SLIDE 2 — Contexte et problematique

**Probleme central :**
Dans les environnements cloud et les architectures microservices, les secrets (cles API, certificats SSL/TLS, cles de chiffrement) sont souvent :

- Codes en dur dans le code source
- Stockes dans des fichiers de configuration versionnes (Git)
- Partages par email ou messagerie instantanee
- Non renouvelés régulièrement

**Consequence :**
Une simple fuite du depot Git ou du fichier `.env` expose l'ensemble des secrets de l'organisation.

**Question :**
Comment fournir aux developpeurs un moyen simple et securise de stocker, acceder et renouveler leurs secrets, sans jamais les exposer dans le code ?

---

## SLIDE 3 — Objectifs du projet

1. Developper une interface web de gestion des secrets integree a OpenStack Barbican
2. Permettre aux applications tierces de recuperer leurs secrets via une API REST securisee
3. Automatiser le renouvellement des certificats SSL/TLS et des paires de cles RSA
4. Isoler les ressources de chaque utilisateur via des projets OpenStack Keystone dedies
5. Notifier les proprietaires de chaque action sur leurs secrets (creation, modification, suppression, acces API)

---

## SLIDE 4 — Architecture generale

```
         Developpeur / Utilisateur
                  |
                  v
         [ BarbiLink — Interface Web ]
         [ Django 6 + HTMX + Bootstrap 5 ]
                  |
        __________|___________
       |                      |
       v                      v
 OpenStack Keystone    OpenStack Barbican
 (Authentification,    (Stockage chiffre
  isolation projets)    des secrets)
```

**Flux principal :**
1. L'utilisateur s'authentifie via Keystone
2. Il cree une application — un projet Keystone isole est genere
3. Il ajoute des secrets — stockes chiffres dans Barbican
4. Il genere un jeton d'acces pour son application tierce
5. L'application tierce lit le secret via l'API REST de BarbiLink

---

## SLIDE 5 — Technologies utilisees

| Categorie | Technologie | Role |
|-----------|-------------|------|
| Backend | Django 6 (Python 3.12) | Framework principal |
| Frontend | Bootstrap 5 + HTMX | UI responsive, requetes partielles |
| Secrets | OpenStack Barbican 7.3 | Stockage chiffre des secrets |
| Identite | OpenStack Keystone | Authentification et isolation |
| Cryptographie | pyOpenSSL, cryptography | Generation SSL/TLS et RSA |
| Certificats | ACME (Let's Encrypt) | Renouvellement automatique |
| Email | Gmail SMTP | Notifications utilisateur |
| API | Django REST Framework | Endpoints JSON publics |
| Base de donnees | SQLite (dev) / PostgreSQL (prod) | Metadonnees applicatives |

---

## SLIDE 6 — Composants de l'application

L'application est decoupee en quatre modules Django independants :

**accounts**
Inscription, connexion, gestion du profil utilisateur (photo, mot de passe, informations).

**apps_manager**
Creation et gestion des applications. Chaque application correspond a un projet Keystone isole avec ses propres credentials Barbican.

**secrets_manager**
Ajout, renouvellement et suppression des secrets. Trois types supportes : generique, certificat SSL/TLS, paire de cles RSA.

**api_manager**
Generation de jetons d'acces Bearer et exposition de l'API REST publique pour les applications tierces.

---

## SLIDE 7 — Types de secrets supportes

**Secret generique**
- Cle API, mot de passe, token, chaine de connexion
- Stocke comme texte chiffre dans un conteneur Barbican de type `generic`

**Certificat SSL/TLS**
- Upload d'un certificat existant (PEM) ou generation automatique via OpenSSL
- Stocke dans un conteneur Barbican de type `certificate`
- Renouvellement avec archivage de l'ancienne version

**Paire de cles RSA**
- Upload d'une paire existante ou generation automatique (2048/4096 bits)
- Stocke dans un conteneur Barbican de type `rsa`
- Recuperation separee de la cle publique ou privee via l'API

---

## SLIDE 8 — Securite et isolation

**Isolation par projet Keystone**
Chaque application utilisateur possede son propre projet Keystone. Un utilisateur ne peut jamais acceder aux secrets d'un autre utilisateur, meme en cas de defaut applicatif.

**Chiffrement cote Barbican**
Les secrets ne sont jamais stockes en clair dans la base de donnees de BarbiLink. Seules les references Barbican (URLs) sont conservees localement.

**Jetons d'acces a portee limitee**
Chaque jeton Bearer donne acces a un seul secret. La compromission d'un jeton n'expose pas les autres secrets de l'application.

**Deconnexion automatique**
Session expirée apres 3 minutes d'inactivite.

**Audit par email**
Chaque acces API (lecture de secret par une application tierce) declenche une notification email au proprietaire, avec l'adresse IP source.

---

## SLIDE 9 — Interface web — Ecrans principaux

**Dashboard**
Vue d'ensemble : nombre d'applications, secrets, certificats. Graphiques de repartition par type.

**Mes applications**
Liste paginee des applications. Recherche globale. Suppression individuelle ou en masse.

**Detail d'une application**
Liste des secrets avec leur type, date de creation, statut du jeton d'acces. Actions : renouveler, supprimer, generer un jeton.

**Formulaire d'ajout d'un secret**
Formulaire adaptatif avec onglets selon le type de secret choisi (generique / certificat / RSA). Upload de fichiers ou generation automatique.

**Mon compte**
Modification des informations personnelles, photo de profil, changement de mot de passe.

---

## SLIDE 10 — API REST pour applications tierces

**Objectif :** permettre a une application tierce de recuperer ses secrets sans acceder a l'interface web.

**Endpoint unique :**
```
GET /api/v1/secrets/<nom_secret>/
Authorization: Bearer <jeton_64_chars>
```

**Exemple de reponse :**
```json
{
  "nom": "stripe-api-key",
  "type": "generic",
  "valeur": "sk_live_51Hx9zA...",
  "encodage": "text"
}
```

**Securite :**
- Authentification par Bearer Token (256 bits, genere par `secrets.token_hex`)
- Un jeton = un secret (acces croise impossible)
- Notification email au proprietaire a chaque acces
- Aucune donnee sensible loggee cote serveur

**Langages supportes dans la documentation :** cURL, Python, JavaScript, Node.js, PHP

---

## SLIDE 11 — Flux complet : du stockage a l'utilisation

```
[1] Developpeur
    --> Se connecte a BarbiLink
    --> Cree une application "MonApp"
    --> Ajoute le secret "stripe-api-key" (valeur : sk_live_...)
    --> Genere un jeton d'acces pour ce secret
    --> Copie le jeton : a3f8d2c1b4e5...

[2] DevOps
    --> Stocke le jeton dans la variable d'environnement
        BARBILINK_TOKEN=a3f8d2c1b4e5...

[3] Application en production
    --> Au demarrage : GET /api/v1/secrets/stripe-api-key/
        Authorization: Bearer a3f8d2c1b4e5...
    --> Recoit : { "valeur": "sk_live_..." }
    --> Utilise la cle sans jamais l'ecrire dans le code
```

---

## SLIDE 12 — Notifications et traçabilite

Chaque action sur la plateforme declenche une notification email non bloquante :

| Action | Notification envoyee |
|--------|----------------------|
| Inscription | Email de bienvenue |
| Creation d'application | Confirmation avec nom de l'app |
| Modification d'application | Alerte avec ancien et nouveau nom |
| Suppression d'application | Alerte avec liste des secrets supprimes |
| Suppression en masse | Alerte avec liste de toutes les apps/secrets supprimes |
| Ajout d'un secret | Confirmation de stockage dans Barbican |
| Renouvellement d'un secret | Confirmation avec mode (manuel/automatique) |
| Generation d'un jeton | Rappel de ne le partager qu'avec des tiers de confiance |
| Renouvellement d'un jeton | Alerte d'invalidation de l'ancien jeton |
| Acces API par une app tierce | Alerte avec IP source et secret consulte |

---

## SLIDE 13 — Defis techniques rencontres

**Integration Keystone + Barbican**
Chaque requete vers Barbican necessite un token Keystone scope sur le bon projet. La gestion du cycle de vie des tokens (obtention, scope, expiration) a necessite une couche d'abstraction specifique.

**Isolation forte des utilisateurs**
Garantir qu'un utilisateur ne peut acceder qu'a ses propres projets Keystone et secrets Barbican, y compris via les endpoints HTMX qui recoivent des IDs en parametres POST.

**Renouvellement avec archivage**
Lors du renouvellement, l'ancienne version du secret doit etre conservee dans Barbican (archivage) et la nouvelle version activee, sans interruption de service pour les applications tierces.

**Interface reactive sans rechargement complet**
L'utilisation d'HTMX pour charger les partiels de l'interface (creation d'app, ajout de secret, detail d'app) a necessite une gestion fine des scripts JavaScript injectes dynamiquement et des conflits de noms de fonctions entre partiels.

---

## SLIDE 14 — Bilan et perspectives

**Ce qui a ete realise**
- Application web complete et fonctionnelle
- Integration effective avec Keystone et Barbican
- API REST documentee avec exemples multi-langages
- Systeme de notifications email complet
- Interface responsive avec gestion mobile

**Perspectives d'evolution**
- Endpoint API en ecriture (POST) : permettre a une app tierce de creer un secret directement
- Rotation automatique planifiee des secrets (tache cron)
- Support multi-utilisateurs avec partage de secrets entre equipes
- Integration CI/CD : plugin pour GitHub Actions / GitLab CI
- Tableau de bord d'audit avec historique des acces API
- Support des secrets de type `symmetric` (cles de chiffrement symetriques)

---

## SLIDE 15 — Conclusion

**BarbiLink repond a la problematique initiale :**

- Les secrets ne transitent plus par le code source ni par Git
- Chaque secret est chiffre et isole dans Barbican sous un projet Keystone dedie
- Les applications tierces peuvent recuperer leurs secrets a la demande via une API securisee
- Chaque acces est tracable et notifie au proprietaire
- Le renouvellement des secrets est simple et sans interruption de service

**Demonstration disponible sur :** `http://<ip-serveur>:8000/`

---

*Rachel ANABA NGOUMOU & Harvis FOTSEU Landry — Master 2 Securite Cloud — Saint-Jean Ingenieur — 2025-2026*

---

---
# ANALYSE : FONCTIONNALITES PREVUES vs. FONCTIONNALITES REALISEES
---

## SLIDE 16 — Fonctionnalites prevues (diagramme de cas d'utilisation)

Le diagramme de cas d'utilisation identifiait les acteurs et fonctionnalites suivants :

**Acteurs prevus :**
- Utilisateur humain (developpeur, proprietaire des secrets)
- Application tierce (consommatrice de secrets via API)
- Orchestrateur interne (composant de fond pour l'automatisation)
- OpenStack Keystone (service d'identite)
- OpenStack Barbican (service de stockage des secrets)
- Service mail (notifications)
- Autorite de certification (renouvellement des certificats)

**Fonctionnalites prevues :**
1. Gerer son compte (creer, modifier, supprimer, se connecter, se deconnecter)
2. Configurer le renouvellement automatique des secrets
3. Gerer ses applications (visualiser, ajouter, supprimer)
4. Ajouter un secret
5. Renouveler un secret
6. Revoquer un ancien secret
7. Recuperer un secret (via API tierce)
8. Notifier (service mail)
9. S'authentifier via Keystone (prerequis de toute action sensible)

---

## SLIDE 17 — Fonctionnalites realisees : bilan complet

### Entierement realisees

| Cas d'utilisation prevu | Statut | Ce qui a ete mis en place |
|-------------------------|--------|---------------------------|
| Creer un compte | Realise | Formulaire d'inscription avec creation d'un utilisateur Keystone associe |
| Modifier mon compte | Realise | Modification du profil (nom, prenom, email, photo de profil) |
| Se connecter | Realise | Authentification Django + obtention d'un token Keystone en session |
| Se deconnecter | Realise | Deconnexion manuelle + deconnexion automatique apres 3 min d'inactivite |
| Supprimer mon compte | Realise | Suppression du compte Django et des credentials Keystone associes |
| Visualiser les applications | Realise | Liste paginee (6 par page), dashboard avec statistiques et graphiques |
| Ajouter une application | Realise | Creation d'un projet Keystone isole + enregistrement dans la base locale |
| Supprimer une application | Realise | Suppression individuelle ou en masse (avec nettoyage Barbican et Keystone) |
| Ajouter un secret | Realise | 3 types : generique, certificat SSL/TLS, paire de cles RSA (upload ou generation) |
| Renouveler un secret (manuel) | Realise | Bouton de renouvellement dans l'interface, archivage de l'ancienne version dans Barbican |
| Revoquer un ancien secret | Realise | Lors du renouvellement, l'ancienne ref Barbican est archivee (ref_old_conteneur) |
| Recuperer un secret (API tierce) | Realise | GET /api/v1/secrets/<nom>/ avec authentification Bearer Token |
| Notifier | Realise | 12 types de notifications email non bloquantes (creation, modification, suppression, acces API...) |
| S'authentifier via Keystone | Realise | Token Keystone obtenu a la connexion, scope par projet pour chaque operation Barbican |

### Partiellement realisee

| Cas d'utilisation prevu | Statut | Etat reel |
|-------------------------|--------|-----------|
| Configurer le renouvellement automatique | Partiel | Le moteur de renouvellement automatique est entierement code (thread daemon + commande Django). La configuration des parametres par secret (duree de validite, delai d'anticipation) est presente dans le modele. L'interface de configuration dediee a l'orchestrateur (prevue pour un role administrateur) n'a pas ete finalisee. |
| Autorite de certification | Partiel | La generation locale de certificats via OpenSSL est implementee (dossier CA_OpenSSL). La librairie ACME (Let's Encrypt) est integree dans les dependances mais le flux complet d'obtention et de renouvellement automatique via ACME n'a pas ete finalise. |

### Fonctionnalites non prevues mais realisees (bonus)

- Suppression en masse d'applications et de secrets avec notification groupee
- Generation et renouvellement de jetons d'acces Bearer par secret depuis l'interface
- Barre de recherche globale avec filtrage en temps reel (HTMX)
- Dashboard avec graphiques (repartition des secrets par type, progression)
- Interface entierement reactive sans rechargement de page (HTMX)
- Pagination, tri et recherche sur la liste des applications
- Deconnexion automatique par inactivite (securite session)
- Commande Django `manage.py auto_renewal` pour declencher le renouvellement manuellement

---

## SLIDE 18 — Comment avons-nous atteint les objectifs ?

### Objectif 1 : Integrer Barbican pour le stockage securise des secrets

**Ce que nous avons mis en place :**

La librairie `python-barbicanclient` a ete utilisee comme client officiel pour communiquer avec l'API Barbican. Nous avons cree une couche d'abstraction dans `secrets_manager/fonctions.py` qui encapsule toutes les operations (creation, lecture, suppression de secrets et de conteneurs). Cette couche gere les erreurs de connexion de facon uniforme via une exception personnalisee `BarbicanConnectionError`.

Trois types de conteneurs Barbican sont supportes, chacun correspondant a un besoin metier distinct :
- `generic` pour les cles API et mots de passe
- `certificate` pour les certificats SSL/TLS au format PEM
- `rsa` pour les paires de cles asymetriques

La base de donnees Django ne stocke jamais les valeurs des secrets. Elle conserve uniquement les references Barbican (URLs), ce qui garantit que meme un acces non autorise a la base de donnees ne compromet pas les secrets.

---

### Objectif 2 : Automatiser le renouvellement des certificats SSL/TLS

**Ce que nous avons mis en place :**

Un thread daemon Python est demarre automatiquement au lancement de Django, via la methode `ready()` de `SecretsManagerConfig` (`secrets_manager/apps.py`). Ce thread tourne en arriere-plan, interroge la base de donnees toutes les heures et renouvelle automatiquement tout secret dont la date d'expiration approche du seuil configurable (`delai_anticipation`).

Le processus de renouvellement (`_effectuer_renouvellement`) :
1. Genere un nouveau secret dans Barbican (nouvelle version)
2. Archive l'ancienne reference dans le champ `ref_old_conteneur`
3. Met a jour `ref_new_conteneur` avec la nouvelle reference
4. Recalcule la prochaine date d'expiration
5. Envoie une notification email au proprietaire

Une commande de gestion Django (`manage.py auto_renewal`) permet de declencher ce cycle manuellement pour les tests et la maintenance.

---

### Objectif 3 : Isoler les ressources par projet Keystone

**Ce que nous avons mis en place :**

A chaque creation d'application dans BarbiLink, un projet Keystone dedie est cree automatiquement via l'API admin de Keystone. Des credentials d'application Keystone (application credentials) sont generes pour ce projet et associes a l'utilisateur.

Chaque operation vers Barbican utilise un token Keystone scope sur le projet concerne (`token_keystone_scope`). Cela signifie qu'un token obtenu pour le projet A ne peut pas acceder aux ressources du projet B dans Barbican. L'isolation est garantie par Keystone lui-meme, pas seulement par des verifications applicatives.

Lors de la suppression d'une application, le projet Keystone est supprime et les credentials associes sont revolques.

---

### Objectif 4 : Fournir une API pour les applications tierces

**Ce que nous avons mis en place :**

Un module `api_manager` a ete cree avec :
- Un modele `TokenAcces` qui associe un jeton unique (256 bits, genere par `secrets.token_hex(32)`) a un conteneur de secret (relation OneToOne)
- Une vue `api_lire_secret_view` exposee publiquement (`@csrf_exempt`) qui valide le Bearer Token, verifie que le jeton correspond bien au secret demande, recupere le payload depuis Barbican via un token admin scope, et retourne une reponse JSON normalisee

Le champ `encodage` de la reponse (`text` ou `base64`) permet au client de savoir comment decoder la valeur, notamment pour les fichiers binaires uploades directement.

Chaque acces API declenche une notification email au proprietaire du secret avec l'adresse IP de l'appelant, assurant une traçabilite complete.

---

## SLIDE 19 — Architecture technique detaillee

```
Navigateur
    |
    |-- HTMX (requetes partielles JSON/HTML)
    |
    v
Django 6 (Python 3.12)
    |
    |-- accounts/         Inscription, login, profil
    |   |-- Keystone API  Creation utilisateur, obtention token
    |
    |-- apps_manager/     Applications, projets, dashboard
    |   |-- Keystone API  Creation/suppression projets, app credentials
    |
    |-- secrets_manager/  Secrets (generique, SSL, RSA)
    |   |-- Barbican API  Conteneurs, secrets, payloads chiffres
    |   |-- Thread daemon Renouvellement automatique (toutes les heures)
    |   |-- OpenSSL/ACME  Generation locale de certificats
    |
    |-- api_manager/      API REST publique + tokens d'acces
        |-- Barbican API  Lecture du payload via token admin scope
        |-- SMTP Gmail    Notifications non bloquantes
```

**Modele de donnees simplifie :**

```
Utilisateur (Django)
    |
    +-- Projet (1 par application)
    |       id_projet = projet Keystone
    |
    +-- Application
    |       nom_app, id_app (app credentials Keystone)
    |
    +-- ConteneurSecret (1 par secret)
    |       type_conteneur, nom_conteneur
    |       ref_old_conteneur, ref_new_conteneur  <- references Barbican
    |       date_expiration, duree_validite, delai_anticipation
    |
    +-- Secret (1 a N par conteneur)
    |       ref_secret  <- reference Barbican
    |       type_secret (certificate, private, public, generic)
    |
    +-- TokenAcces (0 ou 1 par conteneur)
            token  <- Bearer token 256 bits
```

---

*Rachel ANABA NGOUMOU & Harvis FOTSEU Landry — Master 2 Securite Cloud — Saint-Jean Ingenieur — 2025-2026*
