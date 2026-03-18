from django import forms

class AjouterSecretForm(forms.Form):

    id_projet = forms.CharField(widget=forms.HiddenInput())
    nom_secret = forms.CharField(
        max_length=255,
        widget=forms.TextInput(attrs={"placeholder": "ex: api-key-production"}),
    )
    duree_validite = forms.IntegerField(
        min_value=1,
        widget=forms.NumberInput(attrs={"placeholder": "365"}),
    )
    frequence_rotation = forms.ChoiceField(
        choices=[
            (1,    "Quotidienne"),
            (7,   "Hebdomadaire"),
            (30,      "Mensuelle"),
            (90,  "Trimestrielle"),
            (365,       "Annuelle"),
        ],
        initial=30,
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

    def clean(self):
        cleaned_data = super().clean()
        type_secret  = cleaned_data.get("type_secret")
        api_type     = cleaned_data.get("api_type")

        # Validation SSL/TLS — génération
        if type_secret == "ssl":
            ssl_cert = cleaned_data.get("ssl_cert_file")
            ssl_key  = cleaned_data.get("ssl_key_file")

            # Si pas d'upload, les champs DN sont obligatoires
            if not ssl_cert and not ssl_key:
                for champ in ["ssl_domaine", "ssl_organisation", "ssl_pays",
                               "ssl_region", "ssl_ville"]:
                    if not cleaned_data.get(champ):
                        self.add_error(champ, "Ce champ est requis pour la génération.")

        # Validation clé API — upload
        if type_secret == "api":
            if api_type == "unique" and not cleaned_data.get("api_key_file"):
                pass  # génération automatique acceptée
            if api_type == "paire":
                if (cleaned_data.get("api_public_key_file") and
                        not cleaned_data.get("api_private_key_file")):
                    self.add_error("api_private_key_file", "La clé privée est requise.")

        return cleaned_data