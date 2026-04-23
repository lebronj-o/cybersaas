"""
CyberSaaS v2 - Auth Supabase + Design cyber
"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
from supabase import create_client, Client
from scanner.network import run_network_scan
from scanner.access import evaluate_access, ACCESS_CHECKLIST
from scanner.compliance import evaluate_compliance, COMPLIANCE_CHECKS
from reports.generator import generate_html_report

SUPABASE_URL = "https://ydvsvqtherxswqychbkr.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlkdnN2cXRoZXJ4c3dxeWNoYmtyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzY5NjQwNjAsImV4cCI6MjA5MjU0MDA2MH0.fNMpkJBew17NCM_S7EIKpYagQwbFmXP5-vmvHRPXTP0"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

st.set_page_config(page_title="CyberSaaS", page_icon="🔐", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=Share+Tech+Mono&display=swap');
html, body, .stApp { background: #050507 !important; color: #e0e2ea; }
h1,h2,h3 { font-family: 'Syne', sans-serif !important; }
.stTextInput input { background: #0d0f14 !important; border: 1px solid rgba(0,255,136,0.2) !important; color: #e0e2ea !important; font-family: 'Share Tech Mono', monospace !important; border-radius: 2px !important; }
.stButton > button { background: #00ff88 !important; color: #050507 !important; border: none !important; font-family: 'Syne', sans-serif !important; font-weight: 700 !important; border-radius: 2px !important; }
.stButton > button:hover { background: #00cc6a !important; box-shadow: 0 0 20px rgba(0,255,136,0.3) !important; }
.stTabs [data-baseweb="tab-list"] { background: #0d0f14 !important; border-bottom: 1px solid rgba(0,255,136,0.1) !important; }
.stTabs [data-baseweb="tab"] { background: transparent !important; color: #5a5e6e !important; font-family: 'Share Tech Mono', monospace !important; font-size: 12px !important; }
.stTabs [aria-selected="true"] { color: #00ff88 !important; border-bottom: 2px solid #00ff88 !important; background: transparent !important; }
hr { border-color: rgba(0,255,136,0.1) !important; }
[data-testid="stSidebar"] { display: none; }
</style>
""", unsafe_allow_html=True)

def sign_up(email, password):
    try:
        return supabase.auth.sign_up({"email": email, "password": password}), None
    except Exception as e:
        return None, str(e)

def sign_in(email, password):
    try:
        return supabase.auth.sign_in_with_password({"email": email, "password": password}), None
    except Exception as e:
        return None, str(e)

def sign_out():
    supabase.auth.sign_out()
    st.session_state.clear()
    st.rerun()

def score_color(s):
    if s >= 80: return "#00ff88"
    if s >= 50: return "#ffd32a"
    return "#ff4757"

def score_label(s):
    if s >= 80: return "Bon"
    if s >= 50: return "A ameliorer"
    return "Critique"

def card(label, value, sub, color):
    return f"""<div style="background:#0d0f14;border:1px solid rgba(0,255,136,0.1);
         padding:20px;text-align:center;border-top:2px solid {color};">
      <div style="font-size:10px;color:#5a5e6e;letter-spacing:0.15em;text-transform:uppercase;
           margin-bottom:8px;font-family:'Share Tech Mono',monospace;">{label}</div>
      <div style="font-family:'Syne',sans-serif;font-size:32px;font-weight:800;color:{color};line-height:1;">{value}</div>
      <div style="font-size:11px;color:#5a5e6e;margin-top:6px;font-family:'Share Tech Mono',monospace;">{sub}</div>
    </div>"""

def show_auth():
    st.markdown("""
    <div style="text-align:center;padding:60px 0 40px;">
      <div style="font-family:'Share Tech Mono',monospace;color:#00ff88;font-size:11px;letter-spacing:0.2em;margin-bottom:16px;">// SECURE ACCESS</div>
      <h1 style="font-size:48px;font-weight:800;margin-bottom:8px;">Cyber<span style="color:#00ff88;">SaaS</span></h1>
      <p style="color:#5a5e6e;font-size:13px;font-family:'Share Tech Mono',monospace;">Audit de securite pour PME · 100% gratuit</p>
    </div>
    """, unsafe_allow_html=True)

    _, col, _ = st.columns([1, 1.2, 1])
    with col:
        if "auth_mode" not in st.session_state:
            st.session_state.auth_mode = "login"
        ca, cb = st.columns(2)
        with ca:
            if st.button("Connexion", use_container_width=True):
                st.session_state.auth_mode = "login"
        with cb:
            if st.button("Inscription", use_container_width=True):
                st.session_state.auth_mode = "signup"
        st.markdown("<br>", unsafe_allow_html=True)
        email = st.text_input("Email", placeholder="vous@entreprise.fr", key="auth_email")
        password = st.text_input("Mot de passe", type="password", placeholder="••••••••", key="auth_pass")
        st.markdown("<br>", unsafe_allow_html=True)
        if st.session_state.auth_mode == "login":
            if st.button("Se connecter", use_container_width=True, type="primary"):
                if email and password:
                    with st.spinner("Connexion..."):
                        res, err = sign_in(email, password)
                    if err:
                        st.error(f"Erreur : {err}")
                    else:
                        st.session_state.user = res.user
                        st.session_state.logged_in = True
                        st.rerun()
                else:
                    st.warning("Remplis tous les champs.")
        else:
            if st.button("Creer mon compte", use_container_width=True, type="primary"):
                if email and password:
                    if len(password) < 8:
                        st.warning("Mot de passe trop court (8 caracteres min).")
                    else:
                        with st.spinner("Creation..."):
                            res, err = sign_up(email, password)
                        if err:
                            st.error(f"Erreur : {err}")
                        else:
                            st.success("Compte cree ! Verifie ton email puis connecte-toi.")
                            st.session_state.auth_mode = "login"
                else:
                    st.warning("Remplis tous les champs.")

def show_app():
    user = st.session_state.get("user")
    c1, c2 = st.columns([5, 1])
    with c1:
        st.markdown("""<div style="padding:8px 0 24px;">
          <span style="font-family:'Syne',sans-serif;font-size:22px;font-weight:800;">
            Cyber<span style="color:#00ff88;">SaaS</span></span>
          <span style="font-family:'Share Tech Mono',monospace;font-size:10px;color:#00ff88;
            background:rgba(0,255,136,0.08);border:1px solid rgba(0,255,136,0.2);
            padding:3px 8px;margin-left:12px;">GRATUIT</span>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"<div style='text-align:right;padding-top:12px;font-size:11px;color:#5a5e6e;'>{user.email if user else ''}</div>", unsafe_allow_html=True)
        if st.button("Deconnexion"):
            sign_out()

    tab1, tab2, tab3, tab4 = st.tabs(["// RESEAU", "// ACCES & HUMAIN", "// CONFORMITE", "// RAPPORT"])

    with tab1:
        st.markdown("### Scan reseau")
        c1, c2 = st.columns([3, 1])
        with c1:
            target = st.text_input("", placeholder="monentreprise.fr", label_visibility="collapsed")
        with c2:
            go = st.button("Scanner", type="primary", use_container_width=True)
        if go and target:
            with st.spinner(f"Analyse de {target}..."):
                st.session_state["network_result"] = run_network_scan(target)
        if "network_result" in st.session_state:
            r = st.session_state["network_result"]
            st.divider()
            danger = sum(1 for p in r.open_ports if p.risk == "critical")
            ssl_ok = r.ssl and r.ssl.valid
            c1, c2, c3 = st.columns(3)
            with c1: st.markdown(card("SCORE RESEAU", r.score, "/100", score_color(r.score)), unsafe_allow_html=True)
            with c2: st.markdown(card("PORTS DANGEREUX", danger, "detectes", "#ff4757" if danger > 0 else "#00ff88"), unsafe_allow_html=True)
            with c3: st.markdown(card("SSL", "OK" if ssl_ok else "KO", r.ssl.message if r.ssl else "-", "#00ff88" if ssl_ok else "#ff4757"), unsafe_allow_html=True)
            st.markdown("#### Resultats")
            for f in r.findings:
                st.markdown(f"<span style='font-family:Share Tech Mono,monospace;font-size:13px;'>{f}</span>", unsafe_allow_html=True)
            if r.recommendations:
                st.markdown("#### Recommandations")
                for rec in r.recommendations:
                    st.info(f"-> {rec}")

    with tab2:
        st.markdown("### Acces & erreurs humaines")
        access_answers = {}
        cat_labels = {"mfa": "MFA", "passwords": "Mots de passe", "accounts": "Comptes", "config": "Config"}
        categories = {}
        for check in ACCESS_CHECKLIST:
            categories.setdefault(check.category, []).append(check)
        for cat, checks in categories.items():
            st.markdown(f"#### {cat_labels.get(cat, cat)}")
            for check in checks:
                icon = {"critical": "CRITIQUE", "high": "ELEVE", "medium": "MOYEN"}.get(check.risk_if_no, "")
                ans = st.radio(f"[{icon}] {check.question}", ["Non evalue", "Oui", "Non"], horizontal=True, key=f"acc_{check.id}")
                access_answers[check.id] = True if ans == "Oui" else (False if ans == "Non" else None)
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Calculer le score", type="primary", key="btn_access"):
            st.session_state["access_result"] = evaluate_access(access_answers)
        if "access_result" in st.session_state:
            r = st.session_state["access_result"]
            st.divider()
            sc = score_color(r.score)
            st.markdown(f"""<div style="background:#0d0f14;border:1px solid rgba(0,255,136,0.1);
                 padding:24px;display:inline-block;border-top:2px solid {sc};min-width:180px;text-align:center;">
              <div style="font-size:10px;color:#5a5e6e;letter-spacing:0.15em;text-transform:uppercase;
                   margin-bottom:8px;font-family:'Share Tech Mono',monospace;">SCORE ACCES</div>
              <div style="font-family:'Syne',sans-serif;font-size:48px;font-weight:800;color:{sc};line-height:1;">{r.score}</div>
              <div style="font-size:11px;color:#5a5e6e;font-family:'Share Tech Mono',monospace;">/100 · {score_label(r.score)}</div>
            </div>""", unsafe_allow_html=True)
            if r.recommendations:
                st.markdown("#### Priorites")
                for rec in r.recommendations[:5]:
                    st.warning(f"-> {rec}")

    with tab3:
        st.markdown("### Conformite reglementaire")
        compliance_answers = {}
        reg_groups = {}
        for check in COMPLIANCE_CHECKS:
            reg_groups.setdefault(check.regulation, []).append(check)
        for reg, checks in reg_groups.items():
            with st.expander(f"{reg} — {len(checks)} verifications", expanded=(reg == "RGPD")):
                for check in checks:
                    i = "CRITIQUE" if check.penalty >= 15 else "ELEVE" if check.penalty >= 10 else "MOYEN"
                    ans = st.radio(f"[{i}] {check.requirement}", ["Non evalue", "Conforme", "Non conforme"], horizontal=True, key=f"comp_{check.id}")
                    compliance_answers[check.id] = True if ans == "Conforme" else (False if ans == "Non conforme" else None)
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Evaluer", type="primary", key="btn_comp"):
            st.session_state["compliance_result"] = evaluate_compliance(compliance_answers)
        if "compliance_result" in st.session_state:
            r = st.session_state["compliance_result"]
            st.divider()
            cols = st.columns(3)
            for i, (domain, ds) in enumerate(r.domain_scores.items()):
                sc = score_color(ds.score)
                with cols[i]:
                    st.markdown(f"""<div style="background:#0d0f14;border:1px solid rgba(0,255,136,0.1);
                         padding:20px;text-align:center;border-top:2px solid {sc};">
                      <div style="font-size:10px;color:#5a5e6e;letter-spacing:0.12em;text-transform:uppercase;
                           margin-bottom:8px;font-family:'Share Tech Mono',monospace;">{domain}</div>
                      <div style="font-family:'Syne',sans-serif;font-size:32px;font-weight:800;color:{sc};">{ds.score}%</div>
                      <div style="font-size:10px;color:#5a5e6e;font-family:'Share Tech Mono',monospace;">{ds.status}</div>
                    </div>""", unsafe_allow_html=True)
            st.markdown(f"<br><span style='font-family:Share Tech Mono,monospace;color:#00ff88;'>-> {r.report_label}</span>", unsafe_allow_html=True)

    with tab4:
        st.markdown("### Generer le rapport")
        company = st.text_input("Nom de l'entreprise", placeholder="ACME SAS")
        has_n = "network_result" in st.session_state
        has_a = "access_result" in st.session_state
        has_c = "compliance_result" in st.session_state
        st.markdown(f"""<div style="display:flex;gap:24px;margin:16px 0;font-family:'Share Tech Mono',monospace;font-size:12px;">
          <span style="color:{'#00ff88' if has_n else '#3a3d4e'};">{'ok' if has_n else 'o'} Reseau</span>
          <span style="color:{'#00ff88' if has_a else '#3a3d4e'};">{'ok' if has_a else 'o'} Acces</span>
          <span style="color:{'#00ff88' if has_c else '#3a3d4e'};">{'ok' if has_c else 'o'} Conformite</span>
        </div>""", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        if st.button("Generer le rapport", type="primary", disabled=not company):
            if not all([has_n, has_a, has_c]):
                st.warning("Complete les 3 modules d'abord.")
            else:
                with st.spinner("Generation..."):
                    html = generate_html_report(company_name=company,
                        network=st.session_state["network_result"],
                        access=st.session_state["access_result"],
                        compliance=st.session_state["compliance_result"])
                st.download_button("Telecharger le rapport", data=html,
                    file_name=f"rapport_{company.lower().replace(' ','_')}.html", mime="text/html")
                st.success("Ouvre le fichier dans ton navigateur et imprime en PDF.")

if not st.session_state.get("logged_in"):
    show_auth()
else:
    show_app()