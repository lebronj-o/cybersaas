"""
Module Alertes Email — Supabase Edge Functions / SMTP
Envoie un email automatique si score critique detecte
"""
import requests
from dataclasses import dataclass
from typing import List


@dataclass
class AlertConfig:
    email: str
    company: str
    threshold: int = 50  # Score en dessous duquel on alerte


def send_alert_email(
    to_email: str,
    company: str,
    global_score: int,
    critical_findings: List[str],
    supabase_url: str,
    supabase_key: str,
) -> bool:
    """
    Envoie un email d'alerte via Supabase Edge Function.
    Necessite d'avoir configure Resend ou SendGrid dans Supabase.
    """
    findings_html = "".join(
        f"<li style='padding:6px 0;color:#ff4757;font-family:monospace;font-size:13px;'>{f}</li>"
        for f in critical_findings[:5]
    )

    score_color = "#00ff88" if global_score >= 80 else "#ffd32a" if global_score >= 50 else "#ff4757"
    score_label = "Bon" if global_score >= 80 else "A ameliorer" if global_score >= 50 else "CRITIQUE"

    html_body = f"""
    <!DOCTYPE html>
    <html>
    <head>
    <meta charset="UTF-8">
    <style>
      body {{ background:#050507; color:#e0e2ea; font-family:'DM Sans',sans-serif; margin:0; padding:0; }}
      .wrap {{ max-width:600px; margin:0 auto; padding:40px 24px; }}
      .header {{ text-align:center; padding:32px 0; border-bottom:1px solid rgba(0,255,136,0.1); }}
      .logo {{ font-size:24px; font-weight:800; color:#e0e2ea; }}
      .logo span {{ color:#00ff88; }}
      .score-block {{ text-align:center; padding:40px 0; }}
      .score-num {{ font-size:72px; font-weight:800; color:{score_color}; line-height:1; }}
      .score-label {{ font-size:12px; letter-spacing:0.15em; text-transform:uppercase; color:#5a5e6e; margin-top:8px; }}
      .section {{ background:#0d0f14; border:1px solid rgba(255,255,255,0.06); padding:24px; margin:16px 0; }}
      .section-title {{ font-size:11px; letter-spacing:0.15em; text-transform:uppercase; color:#00ff88; margin-bottom:16px; }}
      .btn {{ display:inline-block; background:#00ff88; color:#050507; font-weight:700; padding:14px 32px; text-decoration:none; font-size:14px; }}
      .footer {{ text-align:center; padding:24px 0; font-size:10px; color:#3a3d4e; letter-spacing:0.08em; }}
    </style>
    </head>
    <body>
    <div class="wrap">
      <div class="header">
        <div class="logo">Cyber<span>SaaS</span></div>
        <div style="font-size:11px;color:#5a5e6e;margin-top:8px;letter-spacing:0.1em;">ALERTE DE SECURITE · {company}</div>
      </div>

      <div class="score-block">
        <div class="score-num">{global_score}</div>
        <div style="font-size:14px;color:#5a5e6e;margin-top:4px;">/100</div>
        <div style="display:inline-block;margin-top:12px;padding:6px 16px;background:rgba(255,71,87,0.1);border:1px solid rgba(255,71,87,0.3);color:#ff4757;font-size:11px;letter-spacing:0.1em;text-transform:uppercase;">
          {score_label}
        </div>
      </div>

      <div class="section">
        <div class="section-title">Problemes critiques detectes</div>
        <ul style="list-style:none;padding:0;margin:0;">
          {findings_html}
        </ul>
      </div>

      <div style="text-align:center;padding:32px 0;">
        <a href="https://cybersaas-9x6fr3rfappptavjp6cm5ad.streamlit.app/" class="btn">
          Voir le rapport complet →
        </a>
      </div>

      <div class="footer">
        CyberSaaS · Audit cyber automatise · cybersaas.fr<br>
        Vous recevez cet email car votre score est en dessous du seuil d'alerte.
      </div>
    </div>
    </body>
    </html>
    """

    # Appel Supabase Edge Function (a deployer separement)
    try:
        response = requests.post(
            f"{supabase_url}/functions/v1/send-alert",
            headers={
                "Authorization": f"Bearer {supabase_key}",
                "Content-Type": "application/json",
            },
            json={
                "to": to_email,
                "subject": f"🚨 Alerte sécurité {company} — Score {global_score}/100",
                "html": html_body,
            },
            timeout=10
        )
        return response.status_code == 200
    except Exception as e:
        print(f"Erreur envoi email: {e}")
        return False


def should_alert(score: int, threshold: int = 50) -> bool:
    """Détermine si une alerte doit être envoyée."""
    return score < threshold


def get_critical_findings(network_findings, ad_findings) -> List[str]:
    """Extrait les findings critiques (🔴) des deux modules."""
    all_findings = (network_findings or []) + (ad_findings or [])
    return [f for f in all_findings if "🔴" in f or "CRITIQUE" in f.upper()]
