"""
Générateur de rapport PDF
Prend les 3 résultats de scan et produit un rapport professionnel
"""

from datetime import datetime
from scanner.network import NetworkScanResult
from scanner.access import AccessScanResult
from scanner.compliance import ComplianceResult


def _score_color(score: int) -> str:
    if score >= 80: return "#00c48c"
    if score >= 50: return "#f59e0b"
    return "#ef4444"


def _score_label(score: int) -> str:
    if score >= 80: return "Bon"
    if score >= 50: return "À améliorer"
    return "Critique"


def generate_html_report(
    company_name: str,
    network: NetworkScanResult,
    access: AccessScanResult,
    compliance: ComplianceResult,
) -> str:
    """Génère un rapport HTML complet (convertible en PDF via WeasyPrint)."""

    global_score = (network.score + access.score + compliance.global_score) // 3
    date_str = datetime.now().strftime("%d/%m/%Y")

    # Findings HTML
    def findings_html(findings):
        return "".join(f'<li class="finding">{f}</li>' for f in findings)

    def reco_html(recos):
        return "".join(f'<li class="reco">{r}</li>' for r in recos[:5])  # Top 5

    domain_bars = ""
    for domain, ds in compliance.domain_scores.items():
        color = _score_color(ds.score)
        domain_bars += f"""
        <div class="domain-row">
          <span class="domain-name">{domain}</span>
          <div class="bar-track">
            <div class="bar-fill" style="width:{ds.score}%; background:{color};"></div>
          </div>
          <span class="domain-score" style="color:{color};">{ds.score}%</span>
          <span class="domain-status">{ds.status}</span>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<style>
  @import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=DM+Sans:wght@400;500;600&display=swap');
  * {{ margin:0; padding:0; box-sizing:border-box; }}
  body {{ font-family: 'DM Sans', sans-serif; background:#f8f9fb; color:#1a1d2e; font-size:13px; }}

  .page {{ max-width:800px; margin:0 auto; background:white; }}

  /* HEADER */
  .header {{ background:#08090d; color:white; padding:40px 48px; }}
  .header-top {{ display:flex; justify-content:space-between; align-items:flex-start; margin-bottom:32px; }}
  .brand {{ font-family:'Syne',sans-serif; font-size:18px; font-weight:800; color:#00e5a0; letter-spacing:0.05em; }}
  .report-date {{ font-size:11px; color:#5a5e6e; }}

  .score-hero {{ display:flex; align-items:center; gap:32px; }}
  .score-circle {{
    width:90px; height:90px; border-radius:50%;
    background: conic-gradient({_score_color(global_score)} {global_score * 3.6}deg, #1a1d2e 0deg);
    display:flex; align-items:center; justify-content:center; position:relative;
  }}
  .score-inner {{
    width:72px; height:72px; border-radius:50%; background:#08090d;
    display:flex; flex-direction:column; align-items:center; justify-content:center;
  }}
  .score-num {{ font-family:'Syne',sans-serif; font-size:22px; font-weight:800; color:{_score_color(global_score)}; line-height:1; }}
  .score-max {{ font-size:9px; color:#5a5e6e; }}
  .score-info h2 {{ font-family:'Syne',sans-serif; font-size:22px; font-weight:800; margin-bottom:4px; }}
  .score-info p {{ font-size:12px; color:#6b6f7e; }}
  .score-label {{ display:inline-block; margin-top:8px; padding:4px 12px; border-radius:2px;
    background:rgba(0,229,160,0.15); color:#00e5a0; font-size:11px; font-weight:600; }}

  /* BODY */
  .body {{ padding:40px 48px; }}

  /* SECTION */
  .section {{ margin-bottom:36px; }}
  .section-title {{
    font-family:'Syne',sans-serif; font-size:14px; font-weight:700;
    border-left:3px solid #00e5a0; padding-left:12px; margin-bottom:16px;
  }}

  /* SCORES GRID */
  .scores-grid {{ display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; margin-bottom:32px; }}
  .score-card {{ background:#f8f9fb; border:1px solid #e8eaf0; padding:16px; text-align:center; }}
  .sc-label {{ font-size:10px; color:#6b6f7e; text-transform:uppercase; letter-spacing:0.08em; margin-bottom:8px; }}
  .sc-num {{ font-family:'Syne',sans-serif; font-size:28px; font-weight:800; }}
  .sc-sub {{ font-size:10px; color:#6b6f7e; margin-top:4px; }}

  /* FINDINGS */
  .findings-list {{ list-style:none; }}
  .finding {{ padding:7px 0; border-bottom:1px solid #f0f1f5; font-size:12px; line-height:1.5; }}
  .finding:last-child {{ border-bottom:none; }}

  /* RECOS */
  .reco {{ padding:8px 12px; background:#f8f9fb; border-left:2px solid #3d8bff;
    margin-bottom:6px; font-size:12px; line-height:1.5; list-style:none; }}

  /* DOMAIN BARS */
  .domain-row {{ display:flex; align-items:center; gap:12px; margin-bottom:10px; }}
  .domain-name {{ width:80px; font-size:11px; font-weight:600; }}
  .bar-track {{ flex:1; height:6px; background:#f0f1f5; border-radius:3px; overflow:hidden; }}
  .bar-fill {{ height:100%; border-radius:3px; }}
  .domain-score {{ width:36px; font-size:12px; font-weight:600; text-align:right; }}
  .domain-status {{ width:100px; font-size:10px; color:#6b6f7e; text-transform:capitalize; }}

  /* FOOTER */
  .footer {{ background:#f8f9fb; border-top:1px solid #e8eaf0; padding:20px 48px;
    display:flex; justify-content:space-between; font-size:10px; color:#6b6f7e; }}
</style>
</head>
<body>
<div class="page">

  <div class="header">
    <div class="header-top">
      <div class="brand">CYBERSAAS</div>
      <div class="report-date">Rapport du {date_str}</div>
    </div>
    <div class="score-hero">
      <div class="score-circle">
        <div class="score-inner">
          <div class="score-num">{global_score}</div>
          <div class="score-max">/100</div>
        </div>
      </div>
      <div class="score-info">
        <h2>{company_name}</h2>
        <p>Rapport de sécurité & conformité cyber</p>
        <div class="score-label">{_score_label(global_score)}</div>
      </div>
    </div>
  </div>

  <div class="body">

    <!-- SCORES PAR MODULE -->
    <div class="section">
      <div class="section-title">Scores par domaine</div>
      <div class="scores-grid">
        <div class="score-card">
          <div class="sc-label">Réseau</div>
          <div class="sc-num" style="color:{_score_color(network.score)};">{network.score}</div>
          <div class="sc-sub">Ports · SSL · Services</div>
        </div>
        <div class="score-card">
          <div class="sc-label">Accès humains</div>
          <div class="sc-num" style="color:{_score_color(access.score)};">{access.score}</div>
          <div class="sc-sub">MFA · Mots de passe · Comptes</div>
        </div>
        <div class="score-card">
          <div class="sc-label">Conformité</div>
          <div class="sc-num" style="color:{_score_color(compliance.global_score)};">{compliance.global_score}</div>
          <div class="sc-sub">{compliance.report_label}</div>
        </div>
      </div>
    </div>

    <!-- CONFORMITÉ PAR RÉFÉRENTIEL -->
    <div class="section">
      <div class="section-title">Conformité réglementaire</div>
      {domain_bars}
    </div>

    <!-- FINDINGS -->
    <div class="section">
      <div class="section-title">Problèmes détectés</div>
      <ul class="findings-list">
        {findings_html(network.findings + access.findings + compliance.findings)}
      </ul>
    </div>

    <!-- RECOMMANDATIONS -->
    <div class="section">
      <div class="section-title">Top recommandations prioritaires</div>
      <ul>
        {reco_html(network.recommendations + access.recommendations + compliance.recommendations)}
      </ul>
    </div>

  </div>

  <div class="footer">
    <span>CyberSaaS — Rapport confidentiel · {company_name}</span>
    <span>Généré le {date_str} · v1.0</span>
  </div>

</div>
</body>
</html>"""

    return html


def save_html_report(html: str, path: str = "rapport.html"):
    with open(path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"✅ Rapport HTML sauvegardé : {path}")


def save_pdf_report(html: str, path: str = "rapport.pdf"):
    """Convertit le HTML en PDF via WeasyPrint."""
    try:
        from weasyprint import HTML
        HTML(string=html).write_pdf(path)
        print(f"✅ Rapport PDF sauvegardé : {path}")
    except ImportError:
        print("⚠️  WeasyPrint non installé — pip install weasyprint")
        print("   Le rapport HTML est disponible à la place.")
