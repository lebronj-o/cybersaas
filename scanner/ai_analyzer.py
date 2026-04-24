"""
Module IA — Analyse automatique de fichiers
Upload logs / config / rapports → analyse par Claude API
"""

import json
import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class AIAnalysisResult:
    score: int = 0
    summary: str = ""
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    compliance_gaps: List[str] = field(default_factory=list)
    file_type: str = ""
    raw_response: str = ""


async def analyze_file_with_ai(file_content: str, file_name: str, api_key: str = None) -> AIAnalysisResult:
    """
    Analyse un fichier uploadé via l'API Claude.
    Détecte automatiquement le type de fichier et adapte l'analyse.
    """
    import httpx

    result = AIAnalysisResult()

    # Détecter le type de fichier
    fname = file_name.lower()
    if any(x in fname for x in ["firewall", "fw", "iptables", "pfsense"]):
        result.file_type = "configuration firewall"
    elif any(x in fname for x in ["log", "syslog", "event", "audit"]):
        result.file_type = "logs système"
    elif any(x in fname for x in ["audit", "rapport", "report", "assessment"]):
        result.file_type = "rapport d'audit"
    elif any(x in fname for x in ["ad", "active_directory", "users", "export"]):
        result.file_type = "export Active Directory"
    elif any(x in fname for x in ["config", "cfg", "conf", "settings"]):
        result.file_type = "fichier de configuration"
    else:
        result.file_type = "fichier de sécurité"

    prompt = f"""Tu es un expert en cybersécurité SOC analyst. Analyse ce {result.file_type} et produis une évaluation de sécurité.

FICHIER : {file_name}
CONTENU :
{file_content[:4000]}

Réponds UNIQUEMENT en JSON avec cette structure exacte, sans texte avant ou après :
{{
  "score": <nombre entre 0 et 100>,
  "summary": "<résumé en 2 phrases>",
  "findings": [
    "<problème détecté 1>",
    "<problème détecté 2>",
    "<problème détecté 3>"
  ],
  "recommendations": [
    "<action corrective 1>",
    "<action corrective 2>",
    "<action corrective 3>"
  ],
  "compliance_gaps": [
    "<écart RGPD/NIS2/ISO détecté 1>",
    "<écart RGPD/NIS2/ISO détecté 2>"
  ]
}}

Sois précis et technique. Identifie les vraies vulnérabilités, mauvaises configurations, ou non-conformités."""

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": api_key or "",
                    "anthropic-version": "2023-06-01",
                    "content-type": "application/json",
                },
                json={
                    "model": "claude-sonnet-4-20250514",
                    "max_tokens": 1000,
                    "messages": [{"role": "user", "content": prompt}]
                }
            )

            if response.status_code == 200:
                data = response.json()
                text = data["content"][0]["text"].strip()
                result.raw_response = text

                # Parser le JSON
                json_match = re.search(r'\{.*\}', text, re.DOTALL)
                if json_match:
                    parsed = json.loads(json_match.group())
                    result.score = parsed.get("score", 50)
                    result.summary = parsed.get("summary", "")
                    result.findings = parsed.get("findings", [])
                    result.recommendations = parsed.get("recommendations", [])
                    result.compliance_gaps = parsed.get("compliance_gaps", [])
            else:
                result.score = 50
                result.summary = "Analyse impossible - vérifiez votre clé API."
                result.findings = ["Erreur lors de l'analyse IA"]

    except Exception as e:
        result.score = 50
        result.summary = f"Erreur d'analyse : {str(e)}"
        result.findings = ["Connexion à l'API impossible"]

    return result


def analyze_file_sync(file_content: str, file_name: str, api_key: str = None) -> AIAnalysisResult:
    """Version synchrone pour Streamlit."""
    import requests
    import json
    import re

    result = AIAnalysisResult()

    fname = file_name.lower()
    if any(x in fname for x in ["firewall", "fw", "iptables"]):
        result.file_type = "configuration firewall"
    elif any(x in fname for x in ["log", "syslog", "event"]):
        result.file_type = "logs système"
    elif any(x in fname for x in ["audit", "rapport", "report"]):
        result.file_type = "rapport d'audit"
    elif any(x in fname for x in ["ad", "users", "export"]):
        result.file_type = "export Active Directory"
    else:
        result.file_type = "fichier de sécurité"

    prompt = f"""Tu es un expert en cybersécurité SOC analyst. Analyse ce {result.file_type} et produis une évaluation de sécurité.

FICHIER : {file_name}
CONTENU :
{file_content[:4000]}

Réponds UNIQUEMENT en JSON avec cette structure exacte, sans texte avant ou après :
{{
  "score": <nombre entre 0 et 100>,
  "summary": "<résumé en 2 phrases>",
  "findings": ["<problème 1>", "<problème 2>", "<problème 3>"],
  "recommendations": ["<action 1>", "<action 2>", "<action 3>"],
  "compliance_gaps": ["<écart 1>", "<écart 2>"]
}}

Sois précis et technique. Identifie les vraies vulnérabilités et non-conformités."""

    try:
        response = requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key": api_key or "",
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
            json={
                "model": "claude-sonnet-4-20250514",
                "max_tokens": 1000,
                "messages": [{"role": "user", "content": prompt}]
            },
            timeout=30
        )

        if response.status_code == 200:
            data = response.json()
            text = data["content"][0]["text"].strip()
            json_match = re.search(r'\{.*\}', text, re.DOTALL)
            if json_match:
                parsed = json.loads(json_match.group())
                result.score = parsed.get("score", 50)
                result.summary = parsed.get("summary", "")
                result.findings = parsed.get("findings", [])
                result.recommendations = parsed.get("recommendations", [])
                result.compliance_gaps = parsed.get("compliance_gaps", [])
        else:
            result.score = 50
            result.summary = "Clé API invalide ou quota dépassé."
            result.findings = ["Vérifiez votre clé API Anthropic"]

    except Exception as e:
        result.score = 50
        result.summary = f"Erreur : {str(e)}"
        result.findings = ["Connexion impossible"]

    return result
