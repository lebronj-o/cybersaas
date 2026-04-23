# CyberSaaS — Audit de sécurité pour PME

Outil d'audit cyber gratuit : scan réseau + checklist accès + conformité RGPD/NIS2/ISO 27001 + rapport PDF.

## Installation

```bash
# 1. Cloner / télécharger le projet
cd cybersaas

# 2. Installer les dépendances
pip install -r requirements.txt

# 3. Lancer l'interface
streamlit run ui/app.py
```

L'interface s'ouvre automatiquement sur http://localhost:8501

## Structure

```
cybersaas/
├── scanner/
│   ├── network.py      # Scan ports, SSL, services exposés
│   ├── access.py       # Checklist MFA, mots de passe, comptes
│   └── compliance.py   # Conformité RGPD / NIS2 / ISO 27001
├── reports/
│   └── generator.py    # Génération rapport HTML/PDF
├── ui/
│   └── app.py          # Interface Streamlit
└── requirements.txt
```

## Roadmap

- [ ] Export PDF natif (WeasyPrint)
- [ ] Authentification utilisateur (Supabase)
- [ ] Historique des scans
- [ ] Module cloud M365 / Azure
- [ ] Mode freemium (scan limité gratuit → illimité payant)
