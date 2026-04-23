"""
Module 1 — Scan réseau
Checks : ports ouverts, SSL/TLS, services dangereux exposés
"""

import socket
import ssl
import datetime
from dataclasses import dataclass, field
from typing import List

# Ports dangereux connus
DANGEROUS_PORTS = {
    21:  "FTP — transfert fichiers non chiffré",
    23:  "Telnet — accès distant non chiffré",
    445: "SMB — partage fichiers Windows (EternalBlue)",
    3389:"RDP — bureau à distance exposé",
    3306:"MySQL — base de données exposée",
    5432:"PostgreSQL — base de données exposée",
    6379:"Redis — base de données sans auth par défaut",
    27017:"MongoDB — base de données sans auth par défaut",
    9200:"Elasticsearch — données exposées publiquement",
}

COMMON_PORTS = [21, 22, 23, 25, 53, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017]


@dataclass
class PortResult:
    port: int
    open: bool
    service: str = ""
    risk: str = "low"       # low / medium / high / critical
    message: str = ""


@dataclass
class SSLResult:
    valid: bool
    expiry_date: datetime.datetime = None
    days_remaining: int = 0
    risk: str = "low"
    message: str = ""


@dataclass
class NetworkScanResult:
    target: str
    open_ports: List[PortResult] = field(default_factory=list)
    ssl: SSLResult = None
    score: int = 100          # commence à 100, on déduit les points
    findings: List[str] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)


def scan_port(host: str, port: int, timeout: float = 1.5) -> PortResult:
    """Teste si un port est ouvert."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            service = DANGEROUS_PORTS.get(port, "")
            risk = "critical" if port in DANGEROUS_PORTS else "low"
            return PortResult(port=port, open=True, service=service, risk=risk)
    except (socket.timeout, ConnectionRefusedError, OSError):
        return PortResult(port=port, open=False)


def check_ssl(host: str, port: int = 443) -> SSLResult:
    """Vérifie le certificat SSL : validité + expiration."""
    ctx = ssl.create_default_context()
    try:
        with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
            s.settimeout(5)
            s.connect((host, port))
            cert = s.getpeercert()

        expiry_str = cert["notAfter"]
        expiry = datetime.datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z")
        days = (expiry - datetime.datetime.utcnow()).days

        if days < 0:
            return SSLResult(valid=False, expiry_date=expiry, days_remaining=days,
                             risk="critical", message="Certificat SSL expiré !")
        elif days < 14:
            return SSLResult(valid=True, expiry_date=expiry, days_remaining=days,
                             risk="high", message=f"Certificat expire dans {days} jours")
        elif days < 30:
            return SSLResult(valid=True, expiry_date=expiry, days_remaining=days,
                             risk="medium", message=f"Certificat expire dans {days} jours")
        else:
            return SSLResult(valid=True, expiry_date=expiry, days_remaining=days,
                             risk="low", message=f"Certificat valide ({days} jours restants)")

    except ssl.SSLCertVerificationError:
        return SSLResult(valid=False, risk="critical",
                         message="Certificat SSL invalide ou auto-signé")
    except Exception as e:
        return SSLResult(valid=False, risk="medium",
                         message=f"Impossible de vérifier SSL : {e}")


def run_network_scan(target: str) -> NetworkScanResult:
    """
    Lance le scan réseau complet sur la cible.
    target : domaine ou IP (ex: 'monentreprise.fr')
    """
    # Nettoyer la cible
    host = target.replace("https://", "").replace("http://", "").rstrip("/")

    result = NetworkScanResult(target=host)

    # 1. Scan des ports
    for port in COMMON_PORTS:
        pr = scan_port(host, port)
        if pr.open:
            result.open_ports.append(pr)
            if pr.risk == "critical":
                result.score -= 20
                result.findings.append(f"🔴 Port {port} ouvert ({pr.service})")
                result.recommendations.append(
                    f"Fermer ou filtrer le port {port} ({DANGEROUS_PORTS.get(port, 'service sensible')})"
                )
            elif pr.risk == "high":
                result.score -= 10
                result.findings.append(f"🟠 Port {port} ouvert — à surveiller")

    # 2. Vérification SSL
    result.ssl = check_ssl(host)
    if result.ssl.risk == "critical":
        result.score -= 25
        result.findings.append(f"🔴 SSL : {result.ssl.message}")
        result.recommendations.append("Renouveler immédiatement le certificat SSL")
    elif result.ssl.risk == "high":
        result.score -= 15
        result.findings.append(f"🟠 SSL : {result.ssl.message}")
        result.recommendations.append("Renouveler le certificat SSL sous 2 semaines")
    elif result.ssl.risk == "medium":
        result.score -= 5
        result.findings.append(f"🟡 SSL : {result.ssl.message}")

    result.score = max(0, result.score)

    if not result.findings:
        result.findings.append("✅ Aucun problème réseau critique détecté")

    return result
