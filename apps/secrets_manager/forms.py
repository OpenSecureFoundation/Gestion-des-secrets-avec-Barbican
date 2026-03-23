import re
from django import forms

class AjouterSecretForm(forms.Form):

    projet_id = forms.CharField(widget=forms.HiddenInput())
    nom_secret = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={"placeholder": "ex: api-key-production"}),
    )
    duree_validite = forms.IntegerField(
        min_value=1,
        widget=forms.NumberInput(attrs={"placeholder": "365"}),
    )
    delai_renouvellement = forms.IntegerField(
        min_value=1,
        widget=forms.NumberInput(attrs={"placeholder": "30"}),
    )
    type_secret = forms.ChoiceField(
        choices=[("api", "Clé API"), ("ssl", "Certificat SSL/TLS")],
        widget=forms.RadioSelect,
    )

    # ── Clé API ──
    api_type = forms.ChoiceField(
        choices=[("unique", "Clé unique"), ("paire", "Paire de clés")],
        widget=forms.RadioSelect,
        required=False,
    )
    api_key_file         = forms.FileField(required=False)
    api_public_key_file  = forms.FileField(required=False)
    api_private_key_file = forms.FileField(required=False)

    # ── SSL/TLS ──
    ssl_cert_file    = forms.FileField(required=False)
    ssl_key_file     = forms.FileField(required=False)
    ssl_domaine      = forms.CharField(max_length=255, required=False)
    ssl_organisation = forms.CharField(max_length=255, required=False)
    ssl_pays         = forms.CharField(max_length=2,   required=False)
    ssl_region       = forms.CharField(max_length=255, required=False)
    ssl_ville        = forms.CharField(max_length=255, required=False)

    def clean_nom_secret(self):
        nom = self.cleaned_data.get("nom_secret", "").strip()
        if not re.match(r'^[a-zA-Z0-9_\-]+$', nom):
            raise forms.ValidationError(
                "Seuls les lettres, chiffres, tirets (-) et underscores (_) sont autorisés."
            )
        return nom

    def clean(self):
        cleaned_data = super().clean()
        type_secret  = cleaned_data.get("type_secret")
        api_type     = cleaned_data.get("api_type")

        # ── Validation SSL/TLS ── #
        if type_secret == "ssl":
            ssl_cert = cleaned_data.get("ssl_cert_file")
            ssl_key  = cleaned_data.get("ssl_key_file")

            # Upload partiel : cert sans clé ou clé sans cert
            if ssl_cert and not ssl_key:
                self.add_error("ssl_key_file", "La clé privée est requise avec le certificat.")
            elif ssl_key and not ssl_cert:
                self.add_error("ssl_cert_file", "Le certificat est requis avec la clé privée.")

            # Pas d'upload → génération : champs DN obligatoires
            elif not ssl_cert and not ssl_key:
                for champ in ["ssl_domaine", "ssl_organisation", "ssl_pays",
                               "ssl_region", "ssl_ville"]:
                    if not cleaned_data.get(champ):
                        self.add_error(champ, "Ce champ est requis pour la génération.")

        # ── Validation clé API ── #
        if type_secret == "api":
            if not api_type:
                self.add_error("api_type", "Choisissez un type de clé.")
            elif api_type == "paire":
                priv = cleaned_data.get("api_private_key_file")
                pub  = cleaned_data.get("api_public_key_file")
                if pub and not priv:
                    self.add_error("api_private_key_file", "La clé privée est requise.")
                elif priv and not pub:
                    self.add_error("api_public_key_file", "La clé publique est requise.")

        return cleaned_data