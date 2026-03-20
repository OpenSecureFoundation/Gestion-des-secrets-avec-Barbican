"""
Service de notifications email pour BarbiLink.
Toutes les fonctions sont non-bloquantes : les erreurs d'envoi sont
loggées mais ne propagent jamais d'exception vers l'appelant.
"""
import logging
from django.core.mail import send_mail
from django.conf import settings

logger = logging.getLogger(__name__)

# ── Utilitaire interne ─────────────────────────────────────────────────────────

def _envoyer(sujet, corps, destinataire):
    """Envoie un mail ; absorbe toute exception."""
    try:
        send_mail(
            subject=sujet,
            message=corps,
            from_email=settings.DEFAULT_FROM_EMAIL,
            recipient_list=[destinataire],
            fail_silently=False,
        )
        logger.info("Mail envoyé à %s — sujet : %s", destinataire, sujet)
    except Exception as e:
        logger.error("Échec envoi mail à %s : %s", destinataire, e, exc_info=True)


# ── Compte ────────────────────────────────────────────────────────────────────

def notifier_inscription(utilisateur):
    _envoyer(
        sujet="Bienvenue sur BarbiLink !",
        corps=(
            f"Bonjour {utilisateur.first_name or utilisateur.username} 👋,\n\n"
            "Nous sommes ravis de vous accueillir sur BarbiLink — votre gestionnaire "
            "de secrets sécurisé propulsé par Barbican OpenStack.\n\n"
            "Votre compte a été créé avec succès. Vous pouvez dès maintenant vous "
            "connecter et commencer à gérer vos secrets en toute sécurité.\n\n"
            "À très bientôt sur la plateforme !\n\n"
            "— L'équipe BarbiLink 💜"
        ),
        destinataire=utilisateur.email,
    )


# ── Applications ──────────────────────────────────────────────────────────────

def notifier_app_creee(utilisateur, nom_app):
    _envoyer(
        sujet=f"BarbiLink — Nouvelle application « {nom_app} » créée",
        corps=(
            f"Bonjour {utilisateur.first_name or utilisateur.username} 😊,\n\n"
            f"Votre nouvelle application « {nom_app} » a été créée avec succès sur BarbiLink.\n\n"
            "Vous pouvez maintenant y associer des secrets et configurer les accès.\n\n"
            "— L'équipe BarbiLink 💜"
        ),
        destinataire=utilisateur.email,
    )


def notifier_app_modifiee(utilisateur, ancien_nom, nouveau_nom):
    _envoyer(
        sujet=f"BarbiLink — Application « {ancien_nom} » modifiée",
        corps=(
            f"Bonjour {utilisateur.first_name or utilisateur.username},\n\n"
            f"L'application « {ancien_nom} » a été renommée en « {nouveau_nom} » "
            "sur BarbiLink.\n\n"
            "Si vous n'êtes pas à l'origine de cette modification, contactez-nous immédiatement.\n\n"
            "— L'équipe BarbiLink 💜"
        ),
        destinataire=utilisateur.email,
    )


def notifier_app_supprimee(utilisateur, nom_app):
    _envoyer(
        sujet=f"BarbiLink — Application « {nom_app} » supprimée",
        corps=(
            f"Bonjour {utilisateur.first_name or utilisateur.username},\n\n"
            f"L'application « {nom_app} » ainsi que tous ses secrets associés ont été "
            "supprimés de BarbiLink.\n\n"
            "Si vous n'êtes pas à l'origine de cette suppression, contactez-nous immédiatement.\n\n"
            "— L'équipe BarbiLink 💜"
        ),
        destinataire=utilisateur.email,
    )


# ── Secrets ───────────────────────────────────────────────────────────────────

def notifier_secret_cree(utilisateur, nom_secret, nom_app):
    _envoyer(
        sujet=f"BarbiLink — Secret « {nom_secret} » ajouté",
        corps=(
            f"Bonjour {utilisateur.first_name or utilisateur.username} ,\n\n"
            f"Le secret « {nom_secret} » a été ajouté avec succès à l'application "
            f"« {nom_app} » sur BarbiLink.\n\n"
            "Il est désormais stocké en toute sécurité dans Barbican OpenStack.\n\n"
            "— L'équipe BarbiLink 💜"
        ),
        destinataire=utilisateur.email,
    )


def notifier_secret_modifie(utilisateur, nom_secret, nom_app):
    _envoyer(
        sujet=f"BarbiLink — Secret « {nom_secret} » modifié",
        corps=(
            f"Bonjour {utilisateur.first_name or utilisateur.username},\n\n"
            f"Le secret « {nom_secret} » de l'application « {nom_app} » a été modifié.\n\n"
            "Si vous n'êtes pas à l'origine de cette modification, contactez-nous immédiatement.\n\n"
            "— L'équipe BarbiLink 💜"
        ),
        destinataire=utilisateur.email,
    )


def notifier_secret_supprime(utilisateur, nom_secret, nom_app):
    _envoyer(
        sujet=f"BarbiLink — Secret « {nom_secret} » supprimé",
        corps=(
            f"Bonjour {utilisateur.first_name or utilisateur.username},\n\n"
            f"Le secret « {nom_secret} » de l'application « {nom_app} » a été supprimé de BarbiLink.\n\n"
            "Si vous n'êtes pas à l'origine de cette suppression, contactez-nous immédiatement.\n\n"
            "— L'équipe BarbiLink 💜"
        ),
        destinataire=utilisateur.email,
    )


def notifier_secret_renouvele(utilisateur, nom_secret, nom_app, mode="manuel"):
    mode_txt = "manuellement" if mode == "manuel" else "automatiquement"
    _envoyer(
        sujet=f"BarbiLink — Secret « {nom_secret} » renouvelé",
        corps=(
            f"Bonjour {utilisateur.first_name or utilisateur.username} ,\n\n"
            f"Le secret « {nom_secret} » de l'application « {nom_app} » vient d'être "
            f"renouvelé {mode_txt}.\n\n"
            "La nouvelle version est active et l'ancienne a été archivée dans Barbican.\n\n"
            "— L'équipe BarbiLink 💜"
        ),
        destinataire=utilisateur.email,
    )


# ── Jetons d'accès API ────────────────────────────────────────────────────────

def notifier_token_genere(utilisateur, nom_secret):
    _envoyer(
        sujet=f"BarbiLink — Jeton d'accès généré pour « {nom_secret} »",
        corps=(
            f"Bonjour {utilisateur.first_name or utilisateur.username} ,\n\n"
            f"Un nouveau jeton d'accès API a été généré pour le secret « {nom_secret} ».\n\n"
            "Partagez-le uniquement avec l'application tierce de confiance. "
            "Si ce jeton est compromis, vous pouvez le renouveler à tout moment depuis BarbiLink.\n\n"
            "— L'équipe BarbiLink 💜"
        ),
        destinataire=utilisateur.email,
    )


def notifier_token_renouvele(utilisateur, nom_secret):
    _envoyer(
        sujet=f"BarbiLink — Jeton d'accès renouvelé pour « {nom_secret} »",
        corps=(
            f"Bonjour {utilisateur.first_name or utilisateur.username} ,\n\n"
            f"Le jeton d'accès API du secret « {nom_secret} » vient d'être renouvelé.\n\n"
            "L'ancien jeton est désormais invalide. Les applications tierces utilisant "
            "l'ancien jeton recevront une erreur d'authentification jusqu'à ce qu'elles "
            "soient mises à jour avec le nouveau jeton.\n\n"
            "— L'équipe BarbiLink 💜"
        ),
        destinataire=utilisateur.email,
    )


# ── Accès API tiers ───────────────────────────────────────────────────────────

def notifier_apps_supprimees_masse(utilisateur, noms_apps):
    liste = "\n".join(f"  • {n}" for n in noms_apps)
    _envoyer(
        sujet=f"BarbiLink — {len(noms_apps)} application(s) supprimée(s)",
        corps=(
            f"Bonjour {utilisateur.first_name or utilisateur.username},\n\n"
            f"{len(noms_apps)} application(s) ont été supprimées de BarbiLink :\n{liste}\n\n"
            "Si vous n'êtes pas à l'origine de cette suppression, contactez-nous immédiatement.\n\n"
            "— L'équipe BarbiLink 💜"
        ),
        destinataire=utilisateur.email,
    )


def notifier_secrets_supprimes_masse(utilisateur, noms_secrets):
    liste = "\n".join(f"  • {n}" for n in noms_secrets)
    _envoyer(
        sujet=f"BarbiLink — {len(noms_secrets)} secret(s) supprimé(s)",
        corps=(
            f"Bonjour {utilisateur.first_name or utilisateur.username},\n\n"
            f"{len(noms_secrets)} secret(s) ont été supprimés de BarbiLink :\n{liste}\n\n"
            "Si vous n'êtes pas à l'origine de cette suppression, contactez-nous immédiatement.\n\n"
            "— L'équipe BarbiLink 💜"
        ),
        destinataire=utilisateur.email,
    )


def notifier_acces_api(utilisateur, nom_secret, operation, ip_tierce=None):
    op_txt = "récupéré" if operation == "read" else "stocké"
    ip_info = f" (depuis {ip_tierce})" if ip_tierce else ""
    _envoyer(
        sujet=f"BarbiLink — Accès API : secret « {nom_secret} » {op_txt}",
        corps=(
            f"Bonjour {utilisateur.first_name or utilisateur.username},\n\n"
            f"Une application tierce{ip_info} vient d'accéder au secret "
            f"« {nom_secret} » via l'API BarbiLink ({op_txt}).\n\n"
            "Si cet accès est inattendu, révoquez le jeton immédiatement depuis BarbiLink.\n\n"
            "— L'équipe BarbiLink 💜"
        ),
        destinataire=utilisateur.email,
    )
