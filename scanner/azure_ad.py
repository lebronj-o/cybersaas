"""
Module Azure AD — Scan automatique
Mode simulé : analyse des données JSON fictives
Mode réel  : connexion Graph API Microsoft
"""

import json
import random
from dataclasses import dataclass, field
from typing import List, Dict
from datetime import datetime, timedelta


# ── DONNÉES FICTIVES RÉALISTES ────────────────────────────

def generate_fake_tenant(company_name: str = "ACME SAS") -> dict:
    """Génère un tenant Azure AD fictif mais réaliste."""
    random.seed(hash(company_name) % 1000)

    users = []
    roles = ["Utilisateur", "Manager", "Admin IT", "DRH", "Comptable", "Commercial"]
    departments = ["IT", "Finance", "RH", "Commercial", "Direction", "Juridique"]

    for i in range(1, 21):
        last_login_days = random.choice([1, 2, 5, 10, 30, 60, 90, 180, 365])
        is_admin = i <= 3
        mfa_enabled = random.random() > (0.3 if is_admin else 0.6)
        weak_password = random.random() > 0.7
        is_inactive = last_login_days > 90

        users.append({
            "id": f"user-{i:03d}",
            "displayName": f"Utilisateur {i:02d}",
            "userPrincipalName": f"user{i:02d}@{company_name.lower().replace(' ', '')}.fr",
            "department": random.choice(departments),
            "jobTitle": random.choice(roles),
            "isAdmin": is_admin,
            "mfaEnabled": mfa_enabled,
            "weakPassword": weak_password,
            "lastLoginDays": last_login_days,
            "isInactive": is_inactive,
            "accountEnabled": random.random() > 0.05,
        })

    policies = {
        "mfaRequired": random.random() > 0.5,
        "passwordMinLength": random.choice([6, 8, 10, 12, 14]),
        "passwordExpiry": random.choice([30, 60, 90, 180, 0]),  # 0 = jamais
        "conditionalAccessEnabled": random.random() > 0.6,
        "ssprEnabled": random.random() > 0.5,  # Self-service password reset
        "legacyAuthBlocked": random.random() > 0.5,
        "privilegedAccessManagement": random.random() > 0.7,
    }

    devices = {
        "total": random.randint(10, 50),
        "compliant": random.randint(5, 40),
        "managed": random.randint(8, 45),
        "bitlockerEnabled": random.randint(5, 40),
    }

    return {
        "tenantName": company_name,
        "users": users,
        "policies": policies,
        "devices": devices,
        "scannedAt": datetime.now().isoformat(),
    }


# ── RÉSULTATS ─────────────────────────────────────────────

@dataclass
class UserRisk:
    name: str
    email: str
    risks: List[str]
    severity: str  # low / medium / high / critical


@dataclass
class ADAuditResult:
    score: int = 100
    total_users: int = 0
    admin_count: int = 0
    mfa_enabled_pct: float = 0
    inactive_count: int = 0
    weak_password_count: int = 0
    risky_users: List[UserRisk] = field(default_factory=list)
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    policy_results: Dict[str, bool] = field(default_factory=dict)
    device_results: Dict[str, any] = field(default_factory=dict)


# ── MOTEUR D'ANALYSE ──────────────────────────────────────

def analyze_azure_ad(tenant_data: dict) -> ADAuditResult:
    """Analyse les données Azure AD et produit un score de sécurité."""
    result = ADAuditResult()
    users = tenant_data.get("users", [])
    policies = tenant_data.get("policies", {})
    devices = tenant_data.get("devices", {})

    result.total_users = len(users)

    # ── ANALYSE UTILISATEURS ──────────────────────────────
    admins = [u for u in users if u.get("isAdmin")]
    mfa_enabled = [u for u in users if u.get("mfaEnabled")]
    inactive = [u for u in users if u.get("isInactive")]
    weak_pw = [u for u in users if u.get("weakPassword")]

    result.admin_count = len(admins)
    result.mfa_enabled_pct = round(len(mfa_enabled) / len(users) * 100) if users else 0
    result.inactive_count = len(inactive)
    result.weak_password_count = len(weak_pw)

    # Admins sans MFA — critique
    admins_no_mfa = [u for u in admins if not u.get("mfaEnabled")]
    if admins_no_mfa:
        result.score -= 25
        result.findings.append(f"🔴 {len(admins_no_mfa)} admin(s) sans MFA activé")
        result.recommendations.append("Activer le MFA en priorité absolue sur tous les comptes admin")
        for u in admins_no_mfa:
            result.risky_users.append(UserRisk(
                name=u["displayName"], email=u["userPrincipalName"],
                risks=["Admin sans MFA"], severity="critical"
            ))

    # MFA global
    if result.mfa_enabled_pct < 50:
        result.score -= 20
        result.findings.append(f"🔴 Seulement {result.mfa_enabled_pct}% des utilisateurs ont le MFA activé")
        result.recommendations.append(f"Activer le MFA pour les {len(users) - len(mfa_enabled)} utilisateurs restants")
    elif result.mfa_enabled_pct < 80:
        result.score -= 10
        result.findings.append(f"🟠 {result.mfa_enabled_pct}% des utilisateurs ont le MFA — objectif : 100%")

    # Comptes inactifs
    if inactive:
        result.score -= min(15, len(inactive) * 2)
        result.findings.append(f"🟠 {len(inactive)} compte(s) inactif(s) depuis +90 jours")
        result.recommendations.append("Désactiver ou supprimer les comptes inactifs depuis plus de 90 jours")

    # Mots de passe faibles
    if weak_pw:
        result.score -= min(15, len(weak_pw) * 2)
        result.findings.append(f"🟠 {len(weak_pw)} utilisateur(s) avec mot de passe faible détecté")
        result.recommendations.append("Forcer un changement de mot de passe et renforcer la politique")

    # Trop d'admins
    if result.admin_count > 3:
        result.score -= 10
        result.findings.append(f"🟡 {result.admin_count} comptes admin — recommandation : max 2-3")
        result.recommendations.append("Appliquer le principe du moindre privilège — réduire le nombre d'admins")

    # ── ANALYSE POLICIES ──────────────────────────────────
    result.policy_results = {
        "MFA obligatoire": policies.get("mfaRequired", False),
        "Longueur mot de passe >= 12": policies.get("passwordMinLength", 0) >= 12,
        "Accès conditionnel": policies.get("conditionalAccessEnabled", False),
        "Auth legacy bloquée": policies.get("legacyAuthBlocked", False),
        "Réinitialisation self-service": policies.get("ssprEnabled", False),
        "Gestion accès privilégiés": policies.get("privilegedAccessManagement", False),
    }

    failed_policies = [k for k, v in result.policy_results.items() if not v]
    for p in failed_policies:
        result.score -= 5
        result.findings.append(f"🟡 Politique manquante : {p}")

    if policies.get("passwordMinLength", 0) < 12:
        result.recommendations.append(f"Augmenter la longueur minimale de mot de passe à 12 caractères (actuel: {policies.get('passwordMinLength')})")

    if not policies.get("conditionalAccessEnabled"):
        result.recommendations.append("Activer l'accès conditionnel — bloque les connexions suspectes automatiquement")

    if not policies.get("legacyAuthBlocked"):
        result.recommendations.append("Bloquer l'authentification legacy (SMTP, IMAP) — vecteur d'attaque courant")

    # ── ANALYSE DEVICES ───────────────────────────────────
    total_devices = devices.get("total", 1)
    compliant = devices.get("compliant", 0)
    compliance_pct = round(compliant / total_devices * 100) if total_devices > 0 else 0
    bitlocker_pct = round(devices.get("bitlockerEnabled", 0) / total_devices * 100) if total_devices > 0 else 0

    result.device_results = {
        "total": total_devices,
        "compliant_pct": compliance_pct,
        "bitlocker_pct": bitlocker_pct,
        "managed_pct": round(devices.get("managed", 0) / total_devices * 100) if total_devices > 0 else 0,
    }

    if compliance_pct < 70:
        result.score -= 10
        result.findings.append(f"🟠 Seulement {compliance_pct}% des appareils sont conformes")
        result.recommendations.append("Déployer Intune pour gérer et surveiller tous les appareils")

    if bitlocker_pct < 80:
        result.score -= 5
        result.findings.append(f"🟡 BitLocker activé sur seulement {bitlocker_pct}% des appareils")
        result.recommendations.append("Activer BitLocker sur tous les appareils — protège les données en cas de vol")

    result.score = max(0, result.score)

    if not result.findings:
        result.findings.append("✅ Aucun problème critique détecté sur Azure AD")

    return result
