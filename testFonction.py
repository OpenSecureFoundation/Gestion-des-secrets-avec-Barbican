#!/usr/bin/env python3
"""
Script de test standalone pour commander_secret_barbican.
Teste la soumission d'un ordre de génération de clé via Barbican.

Usage:
    python test_commander_secret.py
"""

import time
import requests

# ------------------------------------------------------------------ #
# Configuration — à adapter selon ton environnement                   #
# ------------------------------------------------------------------ #
BARBICAN_URL     = "http://172.16.79.128:9311/v1/"
USER_TOKEN_SCOPE = "gAAAAABh..."   # token Keystone scopé

# Payload — clé symétrique AES-256
PAYLOAD = {
    "type": "key",
    "meta": {
        "name":        "test-cle-symetrique",
        "algorithm":   "aes",
        "bit_length":  256,
        "mode":        "cbc",
        "secret_type": "symmetric",
    }
}


# ------------------------------------------------------------------ #
# Fonction                                                             #
# ------------------------------------------------------------------ #
def commander_secret_barbican(user_token_scope, payload):
    """
    Soumet un ordre de génération à Barbican et attend qu'il soit ACTIVE.

    Args:
        user_token_scope: Token Keystone scopé.
        payload:          Corps de l'ordre à soumettre.

    Returns:
        dict | None: Données de l'ordre si ACTIVE, None si erreur.
    """
    url = f"{BARBICAN_URL}/v1/orders"
    headers = {
        "X-Auth-Token": user_token_scope,
        "Content-Type": "application/json",
    }

    # Soumission de l'ordre
    try:
        response = requests.post(url, json=payload, headers=headers, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"❌ Erreur réseau : {str(e)}")
        return None

    if response.status_code != 202:
        print(f"❌ Erreur Barbican Order : {response.status_code} - {response.text}")
        return None

    order_ref = response.json().get("order_ref")
    print(f"✅ Commande de génération lancée : {order_ref}")

    # Polling jusqu'à ACTIVE
    for tentative in range(1, 11):
        print(f"   Tentative {tentative}/10 — attente de 3 secondes...")
        time.sleep(3)

        try:
            response = requests.get(order_ref, headers=headers, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"❌ Erreur réseau lors du polling : {str(e)}")
            return None

        if response.status_code != 200:
            print(f"❌ Erreur lors du polling : {response.status_code} - {response.text}")
            return None

        order_data = response.json()
        status     = order_data.get("status")
        print(f"   Statut : {status}")

        if status == "ACTIVE":
            print("✅ Commande de génération réussie.")
            return order_data

        if status == "ERROR":
            print(f"❌ Erreur lors de la commande de génération : {order_data}")
            return None

    print("❌ Délai dépassé — l'ordre n'est pas devenu ACTIVE après 10 tentatives.")
    return None


# ------------------------------------------------------------------ #
# Point d'entrée                                                       #
# ------------------------------------------------------------------ #
if __name__ == "__main__":
    print("=" * 50)
    print("  Test commander_secret_barbican")
    print("=" * 50)

    resultat = commander_secret_barbican(
        user_token_scope=USER_TOKEN_SCOPE,
        payload=PAYLOAD,
    )

    if resultat:
        print("\n📦 Résultat complet :")
        for cle, valeur in resultat.items():
            print(f"   {cle}: {valeur}")
    else:
        print("\n💥 Échec du test.")