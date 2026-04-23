"""
Module 2 — Détection erreurs humaines
Checks : mots de passe faibles, MFA, comptes exposés
(Version sans credentials : checklist interactive)
"""

from dataclasses import dataclass, field
from typing import List
import re


@dataclass
class CheckItem:
    id: str
    question: str                  # Question posée au client
    category: str                  # mfa / passwords / accounts / config
    risk_if_no: str                # low / medium / high / critical
    penalty: int                   # Points déduits si "non"
    recommendation: str


@dataclass
class AccessScanResult:
    score: int = 100
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    answers: dict = field(default_factory=dict)


# Checklist des 15 vérifications clés
ACCESS_CHECKLIST: List[CheckItem] = [
    # MFA
    CheckItem("mfa_email", "Le MFA est activé sur les boîtes email (Outlook, Gmail) ?",
              "mfa", "critical", 25,
              "Activer le MFA sur toutes les boîtes email — priorité absolue"),
    CheckItem("mfa_vpn", "Le MFA est activé sur le VPN / accès distant ?",
              "mfa", "critical", 20,
              "Activer le MFA sur le VPN — vecteur d'attaque n°1"),
    CheckItem("mfa_admin", "Le MFA est activé sur les comptes administrateurs ?",
              "mfa", "critical", 25,
              "Activer le MFA sur tous les comptes admin sans exception"),

    # Mots de passe
    CheckItem("pw_policy", "Une politique de mots de passe est en place (12 car. min) ?",
              "passwords", "high", 15,
              "Définir une politique : 12 caractères minimum, majuscule + chiffre + spécial"),
    CheckItem("pw_manager", "Les employés utilisent un gestionnaire de mots de passe ?",
              "passwords", "medium", 10,
              "Déployer un gestionnaire (Bitwarden Teams, 1Password) — ROI immédiat"),
    CheckItem("pw_shared", "Les mots de passe partagés entre collègues sont évités ?",
              "passwords", "high", 15,
              "Interdire le partage de mots de passe — utiliser des comptes nominatifs"),
    CheckItem("pw_default", "Les mots de passe par défaut des équipements ont été changés ?",
              "passwords", "critical", 20,
              "Changer TOUS les mots de passe par défaut (routeurs, NAS, caméras...)"),

    # Comptes
    CheckItem("acc_offboarding", "Les comptes sont désactivés quand un employé part ?",
              "accounts", "high", 15,
              "Mettre en place un processus d'offboarding avec désactivation J+0"),
    CheckItem("acc_inventory", "Un inventaire des comptes actifs existe et est à jour ?",
              "accounts", "medium", 10,
              "Tenir un registre des comptes — revue trimestrielle recommandée"),
    CheckItem("acc_admin_least", "Le principe du moindre privilège est appliqué ?",
              "accounts", "high", 15,
              "Chaque utilisateur n'a accès qu'à ce dont il a besoin — auditer les droits"),

    # Config & bonnes pratiques
    CheckItem("cfg_updates", "Les mises à jour de sécurité sont appliquées régulièrement ?",
              "config", "high", 15,
              "Activer les mises à jour automatiques ou planifier un patch mensuel"),
    CheckItem("cfg_antivirus", "Un antivirus / EDR est déployé sur tous les postes ?",
              "config", "high", 15,
              "Déployer un EDR sur 100% des endpoints — Defender for Business suffit pour les PME"),
    CheckItem("cfg_backup", "Les sauvegardes sont effectuées et testées régulièrement ?",
              "config", "critical", 20,
              "Règle 3-2-1 : 3 copies, 2 supports différents, 1 hors site — tester la restauration"),
    CheckItem("cfg_wifi", "Le réseau WiFi guest est séparé du réseau interne ?",
              "config", "medium", 10,
              "Créer un réseau WiFi invité isolé — empêche les mouvements latéraux"),
    CheckItem("cfg_phishing", "Les employés ont été formés à détecter le phishing ?",
              "config", "high", 15,
              "Former les équipes au phishing — 1 session/an minimum + simulation"),
]


def evaluate_access(answers: dict) -> AccessScanResult:
    """
    Évalue le score à partir des réponses à la checklist.
    answers : dict {check_id: True/False}
    """
    result = AccessScanResult(answers=answers)

    for check in ACCESS_CHECKLIST:
        answered = answers.get(check.id)
        if answered is False:  # Répondu "Non"
            result.score -= check.penalty
            icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(check.risk_if_no, "⚪")
            result.findings.append(f"{icon} {check.question.replace(' ?', '')} → NON")
            result.recommendations.append(check.recommendation)
        elif answered is None:  # Non répondu
            result.score -= check.penalty // 2   # Pénalité partielle
            result.findings.append(f"⚪ {check.question.replace(' ?', '')} → Non évalué")

    result.score = max(0, result.score)

    if not result.findings:
        result.findings.append("✅ Toutes les vérifications d'accès sont conformes")

    return result


def check_password_strength(password: str) -> dict:
    """
    Vérifie la robustesse d'un mot de passe.
    Utile pour l'outil de démonstration / sensibilisation.
    """
    checks = {
        "length": len(password) >= 12,
        "uppercase": bool(re.search(r'[A-Z]', password)),
        "lowercase": bool(re.search(r'[a-z]', password)),
        "digits": bool(re.search(r'\d', password)),
        "special": bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
    }

    score = sum(checks.values())
    strength = {5: "Fort", 4: "Moyen", 3: "Faible", 2: "Très faible", 1: "Dangereux"}.get(score, "Dangereux")

    return {"checks": checks, "score": score, "strength": strength}
