import base64

from secrets_manager.fonctions import generer_cle_asymetrique, generer_cle_symetrique, generer_ssl, stocker_cle_barbican, stocker_cle_unique_conteneur_barbican, stocker_paire_cles_conteneur_barbican, stocker_certificat_barbican


# --------------------------------------------------------------------- #
# FONCTION POUR TRAITER L'AJOUT D'UNE CLE UNIQUE / D'UNE PAIRE DE CLES  #
# --------------------------------------------------------------------- #
def _traiter_cle(bc, données_cle):
    
    api_type              = données_cle["api_type"]
    secret_name           = données_cle["secret_name"]
    api_key_file          = données_cle.get("api_key_file")
    api_private_key_file  = données_cle.get("api_private_key_file")
    api_public_key_file   = données_cle.get("api_public_key_file")

    # ── Upload clé unique ── #
    if api_key_file and api_type == "unique":
        payload = base64.b64encode(api_key_file).decode('ascii') if isinstance(api_key_file, bytes) else api_key_file
        secret_ref = stocker_cle_barbican(
            bc=bc,
            secret_name=secret_name,
            secret_type="symmetric",
            payload=payload,
            payload_content_type="text/plain",
        )
        container_ref = stocker_cle_unique_conteneur_barbican(bc, secret_name, secret_ref)
        return {
            "container_ref":  container_ref,
            "type_conteneur": "generic",
            "secrets": [
                {"nom": secret_name, "type_secret": "symmetric", "ref": secret_ref},
            ]
        }

    # ── Upload paire de clés ── #
    elif api_type == "paire" and (api_private_key_file or api_public_key_file):
        container_ref = stocker_paire_cles_conteneur_barbican(
            bc=bc,
            secret_name=secret_name,
            payload_private=api_private_key_file,
            payload_public=api_public_key_file,
        )
        container = bc.containers.get(container_ref)
        return {
            "container_ref":  container_ref,
            "type_conteneur": "rsa",
            "secrets": [
                {
                    "nom":         f"{secret_name}-private",
                    "type_secret": "asymmetric",
                    "ref":         container.secrets.get("private_key").secret_ref,
                },
                {
                    "nom":         f"{secret_name}-public",
                    "type_secret": "asymmetric",
                    "ref":         container.secrets.get("public_key").secret_ref,
                },
            ]
        }

    # ── Génération clé unique ── #
    elif not api_key_file and api_type == "unique":
        secret_ref = generer_cle_symetrique(bc, secret_name)
        container_ref = stocker_cle_unique_conteneur_barbican(bc, secret_name, secret_ref)
        return {
            "container_ref":  container_ref,
            "type_conteneur": "generic",
            "secrets": [
                {"nom": secret_name, "type_secret": "symmetric", "ref": secret_ref},
            ]
        }

    # ── Génération paire de clés ── #
    elif not api_key_file and api_type == "paire":
        container_ref = generer_cle_asymetrique(bc, secret_name)
        container = bc.containers.get(container_ref)
        return {
            "container_ref":  container_ref,
            "type_conteneur": "rsa",
            "secrets": [
                {
                    "nom":         f"{secret_name}-private",
                    "type_secret": "asymmetric",
                    "ref":         container.secrets.get("private_key").secret_ref,
                },
                {
                    "nom":         f"{secret_name}-public",
                    "type_secret": "asymmetric",
                    "ref":         container.secrets.get("public_key").secret_ref,
                },
            ]
        }

    

# --------------------------------------------------------------------- #
# FONCTION POUR TRAITER L'AJOUT D'UN CERTIFICAT SSL/TLS                 #
# --------------------------------------------------------------------- #
def _traiter_certificat_ssl(bc, données_ssl):
    
    secret_name   = données_ssl["secret_name"]
    ssl_cert_file = données_ssl.get("ssl_cert_file")
    ssl_key_file  = données_ssl.get("ssl_key_file")

    # ── Upload certificat + clé ── #
    if ssl_cert_file and ssl_key_file:
        secret_ref_cert = stocker_certificat_barbican(
            bc=bc,
            secret_name=f"{secret_name}-certificate",
            secret_type="certificate",
            payload=ssl_cert_file,
            payload_content_type="text/plain",
        )
        secret_ref_private = stocker_cle_barbican(
            bc=bc,
            secret_name=f"{secret_name}-private",
            secret_type="private",
            payload=ssl_key_file,
            payload_content_type="text/plain",
        )
        container = bc.containers.create_certificate(
            name=f"{secret_name}-tls",
            certificate=bc.secrets.get(secret_ref_cert),
            private_key=bc.secrets.get(secret_ref_private),
        )
        container_uri = container.store()
        return {
            "container_ref":  container_uri,
            "type_conteneur": "certificate",
            "secrets": [
                {
                    "nom":         f"{secret_name}-certificate",
                    "type_secret": "certificate",
                    "ref":         secret_ref_cert,
                },
                {
                    "nom":         f"{secret_name}-private",
                    "type_secret": "asymmetric",
                    "ref":         secret_ref_private,
                },
            ]
        }

    # ── Génération CSR + CA ── #
    else:
        container_ref = generer_ssl(bc, données_ssl)
        container = bc.containers.get(container_ref)
        return {
            "container_ref":  container_ref,
            "type_conteneur": "certificate",
            "secrets": [
                {
                    "nom":         f"{secret_name}-certificate",
                    "type_secret": "certificate",
                    "ref":         container.secrets.get("certificate").secret_ref,
                },
                {
                    "nom":         f"{secret_name}-private",
                    "type_secret": "asymmetric",
                    "ref":         container.secrets.get("private_key").secret_ref,
                },
            ]
        }
    
