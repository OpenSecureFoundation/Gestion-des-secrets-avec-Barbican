import base64
import datetime
import secrets as secrets_module
from barbicanclient import client as barbican_client
from barbicanclient import exceptions as barbican_exceptions
from keystoneauth1 import identity, session as ks_session
from django.conf import settings
import time
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization



# ── Exceptions personnalisées ──
class BarbicanOrderError(Exception):
    """Levée quand Barbican retourne un statut ERROR sur l'ordre."""
    pass

class BarbicanTimeoutError(Exception):
    """Levée quand l'ordre n'est pas ACTIVE après le délai maximum."""
    pass

class BarbicanConnectionError(Exception):
    """Levée en cas d'erreur réseau ou de connexion à Barbican."""
    pass

class BarbicanContainerError(Exception):
    """Levée quand le conteneur Barbican est inaccessible ou incomplet."""
    pass

class CSRGenerationError(Exception):
    """Levée quand la génération de la CSR échoue."""
    pass

class CAInfrastructureError(Exception):
    """Levée quand les fichiers de la CA (cert ou key) sont introuvables ou corrompus."""
    pass

class CASigningError(Exception):
    """Levée quand la signature de la CSR échoue (CSR invalide, erreur crypto)."""
    pass 


# ------------------------------------------------------------------ #
# FONCTION POUR CREER UN CLIENT BARBICAN                             #
# ------------------------------------------------------------------ #
def get_barbican_client(user_token_scope, projet_id):
    
    try:
        auth = identity.Token(
            auth_url=settings.KEYSTONE_URL,
            token=user_token_scope,
            project_id=projet_id             ###################################################
        )
        sess = ks_session.Session(auth=auth)
        return barbican_client.Client(
            session=sess,
            endpoint=settings.BARBICAN_URL,
        )
    except Exception as e:
        raise BarbicanConnectionError(
            f"Impossible de créer le client Barbican : {str(e)}"
        )

# ------------------------------------------------------------------ #
# FONCTION POUR COMMANDER UNE CLE OU UNE PAIRE DE CLES               #
# ------------------------------------------------------------------ #
def commander_secret_barbican(bc, payload):
   
    # 1. Soumission de l'ordre selon le type                             
    try:
        order_type = payload.get("type")
        meta       = payload.get("meta", {})

        if order_type == "key":
            order = bc.orders.create_key(
                name=meta.get("name"),
                algorithm=meta.get("algorithm"),
                bit_length=meta.get("bit_length"),
                mode=meta.get("mode"),
                payload_content_type="application/octet-stream"
            )
        elif order_type == "asymmetric":
            order = bc.orders.create_asymmetric(
                name=meta.get("name"),
                algorithm=meta.get("algorithm"),
                bit_length=meta.get("bit_length"),
                payload_content_type="text/plain"
            )
        else:
            raise BarbicanOrderError(f"Type d'ordre non supporté : '{order_type}'")

        order.submit()
        print(f"Commande de génération lancée : {order.order_ref}")

    except barbican_exceptions.HTTPClientError as e:
        raise BarbicanConnectionError(
            f"Barbican a refusé l'ordre [HTTP {e.status_code}] : {str(e)}"
        )
    except Exception as e:
        raise BarbicanConnectionError(
            f"Erreur lors de la soumission de l'ordre : {str(e)}"
        )

    # 2. Polling jusqu'à ACTIVE   
    for tentative in range(1, 11):
        print(f"Tentative {tentative}/10 — attente de 1 secondes...")
        time.sleep(1)

        try:
            order = bc.orders.get(order.order_ref)
        except barbican_exceptions.HTTPClientError as e:
            raise BarbicanConnectionError(
                f"Erreur lors du polling de l'ordre : {str(e)}"
            )

        print(f"Statut : {order.status}")

        if order.status == "ACTIVE":
            print("Commande de génération réussie.")
            return order

        if order.status == "ERROR":
            raise BarbicanOrderError(
                f"Barbican a échoué à générer le secret : {order.error_reason}"
            )
    raise BarbicanTimeoutError(
        "L'ordre Barbican n'est pas devenu ACTIVE après 10 tentatives."
    )


# ------------------------------------------------------------------ #
# FONCTION POUR GENERER UNE CLE UNIQUE                               #
# ------------------------------------------------------------------ #
def generer_cle_symetrique(bc, key_name):
    """Génère une clé symétrique 256 bits et la stocke en base64 (text/plain)."""
    raw_key = secrets_module.token_bytes(32)  # 256 bits
    payload_b64 = base64.b64encode(raw_key).decode('ascii')
    secret_ref = stocker_cle_barbican(
        bc=bc,
        secret_name=key_name,
        secret_type="symmetric",
        payload=payload_b64,
        payload_content_type="text/plain",
    )
    return secret_ref


# ------------------------------------------------------------------ #
# FONCTION POUR GENERER UNE PAIRE DE CLES                            #
# ------------------------------------------------------------------ #
def generer_cle_asymetrique(bc, key_name):
    
    order_body = {
        "type": "asymmetric",
        "meta": {
            "name":       key_name,
            "algorithm":  "rsa",
            "bit_length": 2048,
        },
    }
    order = commander_secret_barbican(bc, order_body)
    print(f"Paire de clés asymétrique générée et disponible : {order.container_ref}")
    return order.container_ref


# ------------------------------------------------------------------ #
# FONCTION POUR GENERER UNE CSR A PARTIR D'UNE PAIRE DE CLES         #
# ------------------------------------------------------------------ #
def generer_csr(bc, container_ref, subject_dn):
    
    DN_FIELD_MAP = {
        "CN": NameOID.COMMON_NAME,
        "O":  NameOID.ORGANIZATION_NAME,
        "C":  NameOID.COUNTRY_NAME,
        "OU": NameOID.ORGANIZATIONAL_UNIT_NAME,
        "ST": NameOID.STATE_OR_PROVINCE_NAME,
        "L":  NameOID.LOCALITY_NAME,
    }

    # 1. Récupération du conteneur via le client
    try:
        container = bc.containers.get(container_ref)
    except (barbican_exceptions.HTTPClientError,
            barbican_exceptions.HTTPServerError) as e:
        raise BarbicanConnectionError(
            f"Erreur API Barbican lors de la récupération du conteneur : {str(e)}"
        )
    
    # 2. Extraction de la référence de la clé privée
    # On utilise .secrets au lieu de parser le JSON manuellement
    private_key_secret = container.secrets.get('private_key')
    if not private_key_secret:
        raise BarbicanContainerError("Le conteneur ne contient pas de clé privée pour generer la csr.")
    
    # 3. Récupération du payload (contenu) de la clé privée
    # Le client gère automatiquement les headers et le décodage
    try:
        private_key_payload = private_key_secret.payload
    except (barbican_exceptions.HTTPClientError,
            barbican_exceptions.HTTPServerError) as e:
        raise BarbicanConnectionError(
            f"Erreur API Barbican lors du téléchargement de la clé privée : {str(e)}"
        )

    # 4. Désérialisation de la clé privée (Logique cryptography)
    try:
        private_key = serialization.load_pem_private_key(
            private_key_payload if isinstance(private_key_payload, bytes)
            else private_key_payload.encode(),
            password=None,
        )
    except Exception as e:
        raise BarbicanContainerError(
            f"La clé privée récupérée est invalide ou corrompue : {str(e)}"
        )

    # 5. Construction du DN (Distinguished Name)
    dn_attributes = [
        x509.NameAttribute(DN_FIELD_MAP[cle], valeur)
        for cle, valeur in subject_dn.items()
        if valeur
    ]

        # 6. Génération de la CSR
    try:
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name(dn_attributes))
            .sign(private_key, hashes.SHA256())
        )
        csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        return csr_pem
    except Exception as e:
        raise CSRGenerationError(
            f"Erreur lors de la génération de la CSR : {str(e)}"
        )


# ------------------------------------------------------------------ #
# FONCTION POUR SOUMETTRE UNE CSR A OPENSSL                          #
# ------------------------------------------------------------------ #
def soumettre_csr_openssl(csr_pem, validite_jours):
   
    ca_cert_path = settings.CA_CERT_PATH
    ca_key_path  = settings.CA_KEY_PATH

    # 1. Chargement du certificat de la CA
    try:
        with open(ca_cert_path, "rb") as f:
            ca_cert = x509.load_pem_x509_certificate(f.read())
    except FileNotFoundError:
        raise CAInfrastructureError(f"Certificat CA introuvable à : {ca_cert_path}")
    except Exception as e:
        raise CAInfrastructureError(f"Certificat CA corrompu ou illisible : {str(e)}")

    # 2. Chargement de la clé privée CA
    try:
        with open(ca_key_path, "rb") as f:
            ca_key = serialization.load_pem_private_key(f.read(), password=None)
    except FileNotFoundError:
        raise CAInfrastructureError(f"Clé privée CA introuvable à : {ca_key_path}")
    except Exception as e:
        raise CAInfrastructureError(f"Clé privée CA corrompue ou mot de passe requis : {str(e)}")

    # 3. Chargement et vérification de la CSR
    try:
        csr = x509.load_pem_x509_csr(csr_pem.encode("utf-8"))
    except Exception as e:
        raise CASigningError(f"La CSR fournie n'est pas au format PEM valide : {str(e)}")

    if not csr.is_signature_valid:
        raise CASigningError("La signature de la CSR est mathématiquement invalide.")

    # 4. Signature du certificat
    try:
        maintenant = datetime.datetime.now(datetime.timezone.utc)
        certificat = (
            x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(maintenant)
            .not_valid_after(maintenant + datetime.timedelta(days=validite_jours))
            .add_extension(
                x509.BasicConstraints(ca=False, path_length=None),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        certificat_pem = certificat.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        print("Certificat signé avec succès par la CA OpenSSL !")
        return certificat_pem
    except Exception as e:
        raise CASigningError(f"Erreur technique lors de la signature cryptographique : {str(e)}")


# ------------------------------------------------------------------ #
# FONCTION POUR STOCKER UNE CLE DANS BARBICAN                      #
# ------------------------------------------------------------------ #
def stocker_cle_barbican(bc, secret_name, secret_type, payload, payload_content_type="text/plain"):
    try:
        secret = bc.secrets.create(
            name=secret_name,
            algorithm="aes",
            bit_length=256,
            mode="cbc",
            secret_type=secret_type,
            payload=payload,
            payload_content_type=payload_content_type,
        )
        # On récupère l'URI retournée par la méthode store()
        secret_uri = secret.store()         
        print(f"Secret '{secret_name}' stocké avec succès : {secret_uri}")        
        return secret_uri
    except (barbican_exceptions.HTTPClientError,
            barbican_exceptions.HTTPServerError) as e:
        raise BarbicanConnectionError(
            f"Barbican a refusé la création du secret '{secret_name}' : {str(e)}"
        )
    except Exception as e:
        raise BarbicanConnectionError(
            f"Erreur inattendue lors de la création du secret : {str(e)}"
        )
    

# ------------------------------------------------------------------ #
# FONCTION POUR STOCKER UN CERTIFICAT DANS BARBICAN                      #
# ------------------------------------------------------------------ #
def stocker_certificat_barbican(bc, secret_name, secret_type, payload, payload_content_type="text/plain"):
    try:
        secret = bc.secrets.create(
            name=secret_name,
            bit_length=256,
            secret_type=secret_type,
            payload=payload,
            payload_content_type=payload_content_type,
        )
        # On récupère l'URI retournée par la méthode store()
        secret_uri = secret.store()         
        print(f"Secret '{secret_name}' stocké avec succès : {secret_uri}")        
        return secret_uri
    except (barbican_exceptions.HTTPClientError,
            barbican_exceptions.HTTPServerError) as e:
        raise BarbicanConnectionError(
            f"Barbican a refusé la création du secret '{secret_name}' : {str(e)}"
        )
    except Exception as e:
        raise BarbicanConnectionError(
            f"Erreur inattendue lors de la création du secret : {str(e)}"
        )


# ------------------------------------------------------------------ #
# FONCTION POUR STOCKER UNE PAIRE DE CLES DANS UN CONTENEUR BARBICAN #
# ------------------------------------------------------------------ #
def stocker_paire_cles_conteneur_barbican(bc, secret_name, payload_private, payload_public):
    
    # Stockage de la clé privée
    secret_ref_private = stocker_cle_barbican(
        bc=bc,
        secret_name=f"{secret_name}-private",
        secret_type="private",
        payload=payload_private,
        payload_content_type="application/octet-stream",
    )

    # Stockage de la clé publique
    secret_ref_public = stocker_cle_barbican(
        bc=bc,
        secret_name=f"{secret_name}-public",
        secret_type="public",
        payload=payload_public,
        payload_content_type="application/octet-stream",
    )

    # Création du conteneur RSA
    try:
        container = bc.containers.create_rsa(
            name=f"{secret_name}-keypair",
            private_key=bc.secrets.get(secret_ref_private),
            public_key=bc.secrets.get(secret_ref_public),
        )
        container_uri = container.store()
        print(f"Conteneur RSA créé : {container_uri}")
        return container_uri

    except (barbican_exceptions.HTTPClientError,
            barbican_exceptions.HTTPServerError) as e:
        raise BarbicanConnectionError(
            f"Barbican a refusé la création du conteneur RSA : {str(e)}"
        )


# ------------------------------------------------------------------ #
# FONCTION POUR STOCKER UNE CLE UNIQUE DANS UN CONTENEUR BARBICAN    #
# ------------------------------------------------------------------ #
def stocker_cle_unique_conteneur_barbican(bc, secret_name, secret_ref):
    
    try:
        secret = bc.secrets.get(secret_ref)

        container = bc.containers.create(
            name=f"{secret_name}-container",
            secrets={"api_key": secret},
        )
        container_uri = container.store()
        print(f"Clé unique stockée dans un conteneur : {container_uri}")
        return container_uri

    except (barbican_exceptions.HTTPClientError,
            barbican_exceptions.HTTPServerError) as e:
        raise BarbicanConnectionError(
            f"Barbican a refusé la création du conteneur : {str(e)}"
        )
    except Exception as e:
        raise BarbicanConnectionError(
            f"Erreur inattendue lors de la création du conteneur : {str(e)}"
        )


# ------------------------------------------------------------------ #
# FONCTION POUR SUPPRIMER UN SECRET DANS BARBICAN                    #
# ------------------------------------------------------------------ #
def supprimer_secret_barbican(bc, secret_ref):
    try:
        secret = bc.secrets.get(secret_ref)
        secret.delete()
        print(f"Secret supprimé dans Barbican : {secret_ref}")
        return True
    except barbican_exceptions.HTTPClientError as e:
        if e.status_code == 404:
            print(f"Secret déjà absent de Barbican : {secret_ref}")
            return True
        raise BarbicanConnectionError(
            f"Erreur Barbican lors de la suppression du secret : {str(e)}"
        )
    except Exception as e:
        raise BarbicanConnectionError(
            f"Erreur inattendue lors de la suppression du secret : {str(e)}"
        )


# ------------------------------------------------------------------ #
# FONCTION POUR SUPPRIMER UN CONTENEUR DANS BARBICAN                 #
# ------------------------------------------------------------------ #
def supprimer_conteneur_barbican(bc, container_ref):
    try:
        container = bc.containers.get(container_ref)
        container.delete()
        print(f"Conteneur supprimé dans Barbican : {container_ref}")
        return True
    except barbican_exceptions.HTTPClientError as e:
        if e.status_code == 404:
            print(f"Conteneur déjà absent de Barbican : {container_ref}")
            return True
        raise BarbicanConnectionError(
            f"Erreur Barbican lors de la suppression du conteneur : {str(e)}"
        )
    except Exception as e:
        raise BarbicanConnectionError(
            f"Erreur inattendue lors de la suppression du conteneur : {str(e)}"
        )


# ------------------------------------------------------------------ #
# FONCTION POUR RENOMMER LES SECRETS ET CONTENEUR DANS BARBICAN      #
# ------------------------------------------------------------------ #
def renommer_secrets_conteneur_barbican(bc, conteneur_db, nouveau_nom):
    """
    Recrée tous les secrets et le conteneur Barbican avec un nouveau nom.
    Récupère les payloads existants, supprime les anciens, recrée les nouveaux.
    Retourne : {'container_ref': str, 'secrets': [{'nom', 'type_secret', 'ref'}]}
    """
    SUFFIX_TO_ROLE = {
        "":             "api_key",
        "-private":     "private_key",
        "-public":      "public_key",
        "-certificate": "certificate",
    }

    # 1. Récupérer les payloads depuis Barbican avant suppression
    secrets_reconstruits = []
    for s in conteneur_db.secret.all():
        try:
            bc_secret = bc.secrets.get(s.ref_secret)
            payload      = bc_secret.payload
            content_type = bc_secret.content_types.get("default", "text/plain")
            secret_type  = bc_secret.secret_type
        except Exception as e:
            raise BarbicanConnectionError(
                f"Impossible de récupérer le secret '{s.nom_secret}' depuis Barbican : {str(e)}"
            )
        suffix = s.nom_secret[len(conteneur_db.nom_conteneur):]   # ex: "" ou "-private"
        secrets_reconstruits.append({
            "suffix":       suffix,
            "role":         SUFFIX_TO_ROLE.get(suffix, "api_key"),
            "ancien_nom":   s.nom_secret,
            "nouveau_nom":  f"{nouveau_nom}{suffix}",
            "type_secret":  secret_type,
            "payload":      payload,
            "content_type": content_type,
        })

    # 2. Supprimer l'ancien conteneur (old + new si rotation)
    if conteneur_db.ref_old_conteneur:
        supprimer_conteneur_barbican(bc, conteneur_db.ref_old_conteneur)
    if conteneur_db.ref_new_conteneur:
        supprimer_conteneur_barbican(bc, conteneur_db.ref_new_conteneur)

    # 3. Supprimer les anciens secrets
    for s in conteneur_db.secret.all():
        supprimer_secret_barbican(bc, s.ref_secret)

    # 4. Recréer les secrets avec le nouveau nom
    nouveaux_bc_secrets = {}
    nouveaux_secrets_liste = []
    for s_data in secrets_reconstruits:
        try:
            new_bc_secret = bc.secrets.create(
                name=s_data["nouveau_nom"],
                secret_type=s_data["type_secret"],
                payload=s_data["payload"],
                payload_content_type=s_data["content_type"],
            )
            new_ref = new_bc_secret.store()
        except Exception as e:
            raise BarbicanConnectionError(
                f"Erreur lors de la création du secret '{s_data['nouveau_nom']}' : {str(e)}"
            )
        nouveaux_bc_secrets[s_data["role"]] = bc.secrets.get(new_ref)
        nouveaux_secrets_liste.append({
            "nom":        s_data["nouveau_nom"],
            "type_secret": s_data["type_secret"],
            "ref":        new_ref,
        })

    # 5. Recréer le conteneur du bon type
    type_conteneur = conteneur_db.type_conteneur
    try:
        if type_conteneur == "generic":
            container = bc.containers.create(
                name=f"{nouveau_nom}-container",
                secrets={"api_key": nouveaux_bc_secrets["api_key"]},
            )
        elif type_conteneur == "rsa":
            container = bc.containers.create_rsa(
                name=f"{nouveau_nom}-keypair",
                private_key=nouveaux_bc_secrets["private_key"],
                public_key=nouveaux_bc_secrets["public_key"],
            )
        elif type_conteneur == "certificate":
            container = bc.containers.create_certificate(
                name=f"{nouveau_nom}-tls",
                certificate=nouveaux_bc_secrets["certificate"],
                private_key=nouveaux_bc_secrets["private_key"],
            )
        else:
            raise BarbicanConnectionError(f"Type de conteneur inconnu : '{type_conteneur}'")
        new_container_ref = container.store()
    except BarbicanConnectionError:
        raise
    except Exception as e:
        raise BarbicanConnectionError(
            f"Erreur lors de la création du nouveau conteneur Barbican : {str(e)}"
        )

    return {
        "container_ref": new_container_ref,
        "secrets":       nouveaux_secrets_liste,
    }


# ------------------------------------------------------------------ #
# FONCTION COMPLETE POUR GENERER UN CERTIFICAT SSL                   #
# ------------------------------------------------------------------ #
def generer_ssl(bc, données_ssl):
    
    secret_name    = données_ssl["secret_name"]
    duree_validite = données_ssl["duree_validite"]

    # 1. Génération de la paire de clés asymétrique             
    container_ref = generer_cle_asymetrique(
        bc=bc,
        key_name=f"{secret_name}-keypair",
    )

    # 2. Génération de la CSR       
    csr_pem = generer_csr(
        bc=bc,
        container_ref=container_ref,
        subject_dn={
            "CN": données_ssl["ssl_domaine"],
            "O":  données_ssl["ssl_organisation"],
            "C":  données_ssl["ssl_pays"],
            "ST": données_ssl["ssl_region"],
            "L":  données_ssl["ssl_ville"],
        },
    )

    # 3. Signature du certificat par la CA         
    certificat_pem = soumettre_csr_openssl(
        csr_pem=csr_pem,
        validite_jours=duree_validite,
    )

    # 4. Stockage du certificat dans Barbican   
    secret_ref_cert = stocker_certificat_barbican(
        bc=bc,
        secret_name=f"{secret_name}-certificate",
        secret_type="certificate",
        payload=certificat_pem,
        payload_content_type="text/plain",
    )

    # 5. Ajout du certificat dans le conteneur existant     
    try:
        # Récupération du conteneur existant (clé privée + clé publique)
        container = bc.containers.get(container_ref)

        # Récupération des secrets existants
        private_key = container.secrets.get("private_key")
        certificate = bc.secrets.get(secret_ref_cert)

        # Création d'un nouveau conteneur certificate avec les 3 éléments
        # Barbican ne supporte pas PUT sur les conteneurs existants
        nouveau_container = bc.containers.create_certificate(
            name=f"{secret_name}-tls",
            certificate=certificate,
            private_key=private_key,
        )
        container_ref = nouveau_container.store()
        print(f"Certificat ajouté au conteneur : {container_ref}")

    except (barbican_exceptions.HTTPClientError,
            barbican_exceptions.HTTPServerError) as e:
        raise BarbicanConnectionError(
            f"Impossible de créer le conteneur certificate : {str(e)}"
        )

    return container_ref










