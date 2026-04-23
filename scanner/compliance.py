"""
Module 3 — Conformité NIS2 / RGPD / ISO 27001
Checklist réglementaire avec scoring par domaine
"""

from dataclasses import dataclass, field
from typing import List, Dict


@dataclass
class ComplianceCheck:
    id: str
    domain: str          # Domaine réglementaire
    requirement: str     # Exigence à vérifier
    regulation: str      # NIS2 / RGPD / ISO
    article: str         # Référence légale
    penalty: int         # Impact sur le score (0-20)
    guidance: str        # Ce qu'il faut faire


@dataclass
class DomainScore:
    name: str
    score: int
    max_score: int
    status: str          # conforme / partiel / non-conforme


@dataclass
class ComplianceResult:
    global_score: int = 100
    domain_scores: Dict[str, DomainScore] = field(default_factory=dict)
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    compliant_items: List[str] = field(default_factory=list)
    report_label: str = ""   # "Conforme" / "Partiellement conforme" / "Non conforme"


# Référentiel de conformité — 20 exigences clés
COMPLIANCE_CHECKS: List[ComplianceCheck] = [

    # ── RGPD ──────────────────────────────────────────────────
    ComplianceCheck("rgpd_dpa", "RGPD", "Un DPO ou référent RGPD est désigné",
                    "RGPD", "Art. 37", 10,
                    "Désigner un DPO (obligatoire si données sensibles à grande échelle)"),
    ComplianceCheck("rgpd_register", "RGPD", "Un registre des traitements est tenu à jour",
                    "RGPD", "Art. 30", 15,
                    "Créer et maintenir le registre des activités de traitement"),
    ComplianceCheck("rgpd_consent", "RGPD", "Les consentements sont collectés et documentés",
                    "RGPD", "Art. 7", 15,
                    "Mettre en place un système de gestion des consentements"),
    ComplianceCheck("rgpd_breach", "RGPD", "Un processus de notification de violation existe",
                    "RGPD", "Art. 33", 15,
                    "Définir une procédure de notification CNIL sous 72h en cas de breach"),
    ComplianceCheck("rgpd_dpia", "RGPD", "Des analyses d'impact (DPIA) sont réalisées si nécessaire",
                    "RGPD", "Art. 35", 10,
                    "Réaliser une DPIA pour les traitements à risque élevé"),
    ComplianceCheck("rgpd_retention", "RGPD", "Des durées de conservation des données sont définies",
                    "RGPD", "Art. 5", 10,
                    "Définir et appliquer des politiques de rétention des données"),

    # ── NIS2 ──────────────────────────────────────────────────
    ComplianceCheck("nis2_risk", "NIS2", "Une analyse de risque cyber formelle est réalisée",
                    "NIS2", "Art. 21", 20,
                    "Réaliser une analyse de risque annuelle documentée"),
    ComplianceCheck("nis2_incident", "NIS2", "Un plan de réponse aux incidents est défini",
                    "NIS2", "Art. 21", 20,
                    "Créer un plan de réponse aux incidents avec rôles et procédures"),
    ComplianceCheck("nis2_continuity", "NIS2", "Un plan de continuité d'activité (PCA) existe",
                    "NIS2", "Art. 21", 15,
                    "Documenter le PCA et le tester au moins une fois par an"),
    ComplianceCheck("nis2_supply", "NIS2", "La sécurité de la chaîne d'approvisionnement est évaluée",
                    "NIS2", "Art. 21", 10,
                    "Évaluer les pratiques de sécurité de vos fournisseurs clés"),
    ComplianceCheck("nis2_training", "NIS2", "Des formations cyber sont organisées pour les employés",
                    "NIS2", "Art. 21", 10,
                    "Organiser au minimum 1 formation cyber/an pour tous les employés"),
    ComplianceCheck("nis2_crypto", "NIS2", "Le chiffrement des données sensibles est en place",
                    "NIS2", "Art. 21", 15,
                    "Chiffrer les données sensibles au repos et en transit"),
    ComplianceCheck("nis2_vuln", "NIS2", "Une gestion des vulnérabilités est en place",
                    "NIS2", "Art. 21", 15,
                    "Scanner régulièrement les vulnérabilités et appliquer les patchs"),
    ComplianceCheck("nis2_report", "NIS2", "Les incidents significatifs sont déclarés aux autorités",
                    "NIS2", "Art. 23", 15,
                    "Connaître les obligations de déclaration à l'ANSSI sous 24h/72h"),

    # ── ISO 27001 ──────────────────────────────────────────────
    ComplianceCheck("iso_policy", "ISO 27001", "Une politique de sécurité de l'information est rédigée",
                    "ISO 27001", "A.5.1", 10,
                    "Rédiger et diffuser une politique de sécurité validée par la direction"),
    ComplianceCheck("iso_asset", "ISO 27001", "Un inventaire des actifs informationnels existe",
                    "ISO 27001", "A.8.1", 10,
                    "Lister tous les assets (serveurs, données, logiciels, accès)"),
    ComplianceCheck("iso_access", "ISO 27001", "Une politique de contrôle d'accès est appliquée",
                    "ISO 27001", "A.9.1", 15,
                    "Documenter et appliquer les règles de contrôle d'accès"),
    ComplianceCheck("iso_audit", "ISO 27001", "Des audits internes de sécurité sont réalisés",
                    "ISO 27001", "A.18.2", 10,
                    "Planifier des audits internes annuels ou semestriels"),
    ComplianceCheck("iso_physical", "ISO 27001", "La sécurité physique des locaux est assurée",
                    "ISO 27001", "A.11.1", 10,
                    "Contrôler les accès physiques aux zones sensibles (serveurs, archives)"),
    ComplianceCheck("iso_log", "ISO 27001", "Les logs système sont collectés et conservés",
                    "ISO 27001", "A.12.4", 10,
                    "Centraliser et conserver les logs au moins 12 mois"),
]


def evaluate_compliance(answers: dict) -> ComplianceResult:
    """
    Évalue la conformité à partir des réponses.
    answers : dict {check_id: True/False/None}
    """
    result = ComplianceResult()

    # Initialiser les scores par domaine
    domains = ["RGPD", "NIS2", "ISO 27001"]
    domain_totals = {d: 0 for d in domains}
    domain_max = {d: 0 for d in domains}

    for check in COMPLIANCE_CHECKS:
        domain_max[check.domain] = domain_max.get(check.domain, 0) + check.penalty
        answered = answers.get(check.id)

        if answered is True:
            domain_totals[check.domain] = domain_totals.get(check.domain, 0) + check.penalty
            result.compliant_items.append(f"✅ {check.requirement}")
        elif answered is False:
            result.global_score -= check.penalty
            icon = "🔴" if check.penalty >= 15 else "🟠"
            result.findings.append(
                f"{icon} [{check.regulation} {check.article}] {check.requirement} → NON CONFORME"
            )
            result.recommendations.append(f"[{check.regulation}] {check.guidance}")
        else:  # Non évalué
            result.global_score -= check.penalty // 3
            result.findings.append(f"⚪ [{check.regulation}] {check.requirement} → Non évalué")

    # Calcul scores par domaine
    for domain in domains:
        max_s = domain_max.get(domain, 1)
        curr_s = domain_totals.get(domain, 0)
        pct = int((curr_s / max_s) * 100) if max_s > 0 else 0

        if pct >= 80:
            status = "conforme"
        elif pct >= 50:
            status = "partiel"
        else:
            status = "non-conforme"

        result.domain_scores[domain] = DomainScore(
            name=domain, score=pct, max_score=100, status=status
        )

    result.global_score = max(0, result.global_score)

    # Label global
    if result.global_score >= 80:
        result.report_label = "Globalement conforme"
    elif result.global_score >= 50:
        result.report_label = "Partiellement conforme"
    else:
        result.report_label = "Non conforme — action urgente requise"

    return result
