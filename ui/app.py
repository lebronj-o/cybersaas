"""
CyberSaaS — Interface Streamlit
Lance avec : streamlit run ui/app.py
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
from scanner.network import run_network_scan
from scanner.access import evaluate_access, ACCESS_CHECKLIST
from scanner.compliance import evaluate_compliance, COMPLIANCE_CHECKS
from reports.generator import generate_html_report, save_pdf_report

# ─── CONFIG ───────────────────────────────────────────────
st.set_page_config(
    page_title="CyberSaaS — Audit de sécurité",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# CSS custom
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&display=swap');
  .main { background: #08090d; }
  .stApp { background: #08090d; color: #e0e2ea; }
  h1, h2, h3 { font-family: 'Syne', sans-serif !important; }

  .metric-card {
    background: #0f1117;
    border: 1px solid rgba(255,255,255,0.07);
    padding: 20px;
    border-radius: 4px;
    text-align: center;
  }
  .score-big { font-size: 48px; font-weight: 800; font-family: 'Syne', sans-serif; line-height:1; }
  .score-green { color: #00e5a0; }
  .score-yellow { color: #ffd32a; }
  .score-red { color: #ff4757; }
  .finding-critical { color: #ff4757; }
  .finding-high { color: #ff8c00; }
  .finding-ok { color: #00e5a0; }
  div[data-testid="stProgress"] > div { background: #0f1117; }
</style>
""", unsafe_allow_html=True)


def score_color(score: int) -> str:
    if score >= 80: return "score-green"
    if score >= 50: return "score-yellow"
    return "score-red"


def score_emoji(score: int) -> str:
    if score >= 80: return "✅"
    if score >= 50: return "⚠️"
    return "🚨"


# ─── HEADER ───────────────────────────────────────────────
st.markdown("## 🔐 CyberSaaS — Audit de sécurité gratuit")
st.markdown("Analysez la sécurité de votre entreprise en quelques minutes. Aucune installation requise.")
st.divider()

# ─── TABS ─────────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs(["🌐 Réseau", "👤 Accès & Humain", "📋 Conformité", "📄 Rapport"])

# ─── TAB 1 : RÉSEAU ───────────────────────────────────────
with tab1:
    st.markdown("### Scan réseau")
    st.markdown("Entrez le domaine ou l'IP de votre entreprise pour analyser l'exposition réseau.")

    col1, col2 = st.columns([3, 1])
    with col1:
        target = st.text_input("Domaine ou IP cible", placeholder="ex: monentreprise.fr ou 192.168.1.1")
    with col2:
        st.markdown("<br>", unsafe_allow_html=True)
        launch_scan = st.button("⚡ Lancer le scan", type="primary", use_container_width=True)

    if launch_scan and target:
        with st.spinner(f"Scan de {target} en cours..."):
            result = run_network_scan(target)
            st.session_state["network_result"] = result

    if "network_result" in st.session_state:
        r = st.session_state["network_result"]
        st.divider()

        col_score, col_ports, col_ssl = st.columns(3)
        with col_score:
            css = score_color(r.score)
            st.markdown(f"""
            <div class="metric-card">
              <div style="font-size:12px;color:#5a5e6e;margin-bottom:8px;">SCORE RÉSEAU</div>
              <div class="score-big {css}">{r.score}</div>
              <div style="font-size:11px;color:#5a5e6e;margin-top:4px;">/100</div>
            </div>""", unsafe_allow_html=True)

        with col_ports:
            danger_count = sum(1 for p in r.open_ports if p.risk == "critical")
            st.markdown(f"""
            <div class="metric-card">
              <div style="font-size:12px;color:#5a5e6e;margin-bottom:8px;">PORTS DANGEREUX</div>
              <div class="score-big {'score-red' if danger_count > 0 else 'score-green'}">{danger_count}</div>
              <div style="font-size:11px;color:#5a5e6e;margin-top:4px;">détectés</div>
            </div>""", unsafe_allow_html=True)

        with col_ssl:
            ssl_ok = r.ssl and r.ssl.valid
            st.markdown(f"""
            <div class="metric-card">
              <div style="font-size:12px;color:#5a5e6e;margin-bottom:8px;">CERTIFICAT SSL</div>
              <div class="score-big {'score-green' if ssl_ok else 'score-red'}">{'OK' if ssl_ok else 'KO'}</div>
              <div style="font-size:11px;color:#5a5e6e;margin-top:4px;">{r.ssl.message if r.ssl else '—'}</div>
            </div>""", unsafe_allow_html=True)

        st.markdown("#### Résultats détaillés")
        for finding in r.findings:
            st.markdown(f"- {finding}")

        if r.recommendations:
            st.markdown("#### Recommandations")
            for rec in r.recommendations:
                st.info(f"→ {rec}")


# ─── TAB 2 : ACCÈS & HUMAIN ───────────────────────────────
with tab2:
    st.markdown("### Vérifications accès & erreurs humaines")
    st.markdown("Répondez aux questions suivantes sur vos pratiques actuelles.")

    access_answers = {}
    categories = {}
    for check in ACCESS_CHECKLIST:
        if check.category not in categories:
            categories[check.category] = []
        categories[check.category].append(check)

    cat_labels = {
        "mfa": "🔑 Authentification multi-facteurs (MFA)",
        "passwords": "🔐 Mots de passe",
        "accounts": "👥 Gestion des comptes",
        "config": "⚙️ Configuration & bonnes pratiques",
    }

    for cat, checks in categories.items():
        st.markdown(f"#### {cat_labels.get(cat, cat)}")
        for check in checks:
            risk_badge = {"critical": "🔴", "high": "🟠", "medium": "🟡"}.get(check.risk_if_no, "⚪")
            answer = st.radio(
                f"{risk_badge} {check.question}",
                options=["Non évalué", "Oui ✅", "Non ❌"],
                horizontal=True,
                key=f"access_{check.id}"
            )
            if answer == "Oui ✅":
                access_answers[check.id] = True
            elif answer == "Non ❌":
                access_answers[check.id] = False
            else:
                access_answers[check.id] = None

    if st.button("📊 Calculer le score accès", type="primary"):
        result = evaluate_access(access_answers)
        st.session_state["access_result"] = result

    if "access_result" in st.session_state:
        r = st.session_state["access_result"]
        st.divider()
        css = score_color(r.score)
        st.markdown(f"""
        <div class="metric-card" style="max-width:200px;">
          <div style="font-size:12px;color:#5a5e6e;margin-bottom:8px;">SCORE ACCÈS</div>
          <div class="score-big {css}">{r.score}</div>
        </div>""", unsafe_allow_html=True)
        st.progress(r.score / 100)

        if r.recommendations:
            st.markdown("#### Top priorités")
            for rec in r.recommendations[:5]:
                st.warning(f"→ {rec}")


# ─── TAB 3 : CONFORMITÉ ───────────────────────────────────
with tab3:
    st.markdown("### Conformité réglementaire")
    st.markdown("Évaluez votre conformité RGPD · NIS2 · ISO 27001")

    compliance_answers = {}
    reg_groups = {}
    for check in COMPLIANCE_CHECKS:
        if check.regulation not in reg_groups:
            reg_groups[check.regulation] = []
        reg_groups[check.regulation].append(check)

    reg_icons = {"RGPD": "🇪🇺", "NIS2": "🛡️", "ISO 27001": "📜"}

    for reg, checks in reg_groups.items():
        with st.expander(f"{reg_icons.get(reg,'')} {reg} — {len(checks)} vérifications", expanded=(reg=="RGPD")):
            for check in checks:
                penalty_badge = "🔴" if check.penalty >= 15 else "🟠" if check.penalty >= 10 else "🟡"
                answer = st.radio(
                    f"{penalty_badge} {check.requirement}",
                    options=["Non évalué", "Conforme ✅", "Non conforme ❌"],
                    horizontal=True,
                    key=f"comp_{check.id}"
                )
                if answer == "Conforme ✅":
                    compliance_answers[check.id] = True
                elif answer == "Non conforme ❌":
                    compliance_answers[check.id] = False

    if st.button("📊 Évaluer la conformité", type="primary"):
        result = evaluate_compliance(compliance_answers)
        st.session_state["compliance_result"] = result

    if "compliance_result" in st.session_state:
        r = st.session_state["compliance_result"]
        st.divider()

        cols = st.columns(3)
        for i, (domain, ds) in enumerate(r.domain_scores.items()):
            with cols[i]:
                css = score_color(ds.score)
                st.markdown(f"""
                <div class="metric-card">
                  <div style="font-size:11px;color:#5a5e6e;margin-bottom:6px;">{domain}</div>
                  <div class="score-big {css}">{ds.score}%</div>
                  <div style="font-size:10px;color:#5a5e6e;margin-top:4px;">{ds.status}</div>
                </div>""", unsafe_allow_html=True)

        st.markdown(f"**Verdict global :** {r.report_label}")


# ─── TAB 4 : RAPPORT ──────────────────────────────────────
with tab4:
    st.markdown("### Générer le rapport de conformité")

    company_name = st.text_input("Nom de votre entreprise", placeholder="ex: ACME SAS")

    has_network = "network_result" in st.session_state
    has_access = "access_result" in st.session_state
    has_compliance = "compliance_result" in st.session_state

    col1, col2, col3 = st.columns(3)
    with col1: st.markdown(f"{'✅' if has_network else '⚪'} Module réseau")
    with col2: st.markdown(f"{'✅' if has_access else '⚪'} Module accès")
    with col3: st.markdown(f"{'✅' if has_compliance else '⚪'} Module conformité")

    if st.button("📄 Générer le rapport PDF", type="primary", disabled=not company_name):
        if not all([has_network, has_access, has_compliance]):
            st.warning("⚠️ Complétez les 3 modules avant de générer le rapport.")
        else:
            with st.spinner("Génération du rapport..."):
                html = generate_html_report(
                    company_name=company_name,
                    network=st.session_state["network_result"],
                    access=st.session_state["access_result"],
                    compliance=st.session_state["compliance_result"],
                )
                st.download_button(
                    label="⬇️ Télécharger le rapport HTML",
                    data=html,
                    file_name=f"rapport_cyber_{company_name.lower().replace(' ','_')}.html",
                    mime="text/html",
                )
                st.success("✅ Rapport généré ! Ouvrez-le dans votre navigateur pour l'imprimer en PDF.")
                with st.expander("Aperçu du rapport"):
                    st.components.v1.html(html, height=600, scrolling=True)
