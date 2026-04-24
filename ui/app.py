"""CyberSaaS v3 — Scan automatisé + IA + Dashboard historique"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import json
import time
from supabase import create_client, Client
from scanner.network import run_network_scan
from scanner.azure_ad import generate_fake_tenant, analyze_azure_ad
from scanner.ai_analyzer import analyze_file_sync
from scanner.history import save_scan, get_scan_history
from reports.generator import generate_html_report
from scanner.access import evaluate_access, ACCESS_CHECKLIST
from scanner.compliance import evaluate_compliance, COMPLIANCE_CHECKS

SUPABASE_URL = "https://ydvsvqtherxswqychbkr.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InlkdnN2cXRoZXJ4c3dxeWNoYmtyIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzY5NjQwNjAsImV4cCI6MjA5MjU0MDA2MH0.fNMpkJBew17NCM_S7EIKpYagQwbFmXP5-vmvHRPXTP0"
supabase: Client = create_client(SUPABASE_URL, SUPABASE_KEY)

st.set_page_config(page_title="CyberSaaS", page_icon="🔐", layout="wide", initial_sidebar_state="collapsed")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=Share+Tech+Mono&display=swap');
html,body,.stApp{background:#050507 !important;color:#e0e2ea;}
h1,h2,h3{font-family:'Syne',sans-serif !important;letter-spacing:-0.02em;}
.stTextInput input,.stTextArea textarea{background:#0d0f14 !important;border:1px solid rgba(0,255,136,0.2) !important;color:#e0e2ea !important;font-family:'Share Tech Mono',monospace !important;border-radius:2px !important;}
.stButton>button{background:#00ff88 !important;color:#050507 !important;border:none !important;font-family:'Syne',sans-serif !important;font-weight:700 !important;border-radius:2px !important;transition:all 0.2s !important;}
.stButton>button:hover{background:#00cc6a !important;box-shadow:0 0 20px rgba(0,255,136,0.3) !important;}
.stTabs [data-baseweb="tab-list"]{background:#0d0f14 !important;border-bottom:1px solid rgba(0,255,136,0.1) !important;}
.stTabs [data-baseweb="tab"]{background:transparent !important;color:#5a5e6e !important;font-family:'Share Tech Mono',monospace !important;font-size:12px !important;}
.stTabs [aria-selected="true"]{color:#00ff88 !important;border-bottom:2px solid #00ff88 !important;background:transparent !important;}
.stFileUploader{background:#0d0f14 !important;border:1px dashed rgba(0,255,136,0.3) !important;border-radius:2px !important;}
.stExpander{background:#0d0f14 !important;border:1px solid rgba(0,255,136,0.1) !important;}
hr{border-color:rgba(0,255,136,0.1) !important;}
[data-testid="stSidebar"]{display:none;}
::-webkit-scrollbar{width:4px;}::-webkit-scrollbar-thumb{background:rgba(0,255,136,0.3);}
.stSelectbox>div>div{background:#0d0f14 !important;border:1px solid rgba(0,255,136,0.2) !important;color:#e0e2ea !important;}
</style>
""", unsafe_allow_html=True)

# ── HELPERS ──────────────────────────────────────────────
def sc(s):
    if s>=80: return "#00ff88"
    if s>=50: return "#ffd32a"
    return "#ff4757"

def sl(s):
    if s>=80: return "Bon"
    if s>=50: return "A ameliorer"
    return "Critique"

def card(label, value, sub, color, width="100%"):
    return f"""<div style="background:#0d0f14;border:1px solid rgba(0,255,136,0.08);
        padding:20px;text-align:center;border-top:2px solid {color};width:{width};">
      <div style="font-size:9px;color:#5a5e6e;letter-spacing:0.18em;text-transform:uppercase;
           margin-bottom:8px;font-family:'Share Tech Mono',monospace;">{label}</div>
      <div style="font-family:'Syne',sans-serif;font-size:30px;font-weight:800;color:{color};line-height:1;">{value}</div>
      <div style="font-size:10px;color:#5a5e6e;margin-top:6px;font-family:'Share Tech Mono',monospace;">{sub}</div>
    </div>"""

def finding_row(text):
    return f"<div style='font-family:Share Tech Mono,monospace;font-size:12px;padding:6px 0;border-bottom:1px solid rgba(255,255,255,0.04);'>{text}</div>"

def reco_row(text):
    return f"<div style='font-family:Share Tech Mono,monospace;font-size:12px;padding:8px 12px;background:rgba(61,139,255,0.06);border-left:2px solid #3d8bff;margin-bottom:4px;'>→ {text}</div>"

# ── AUTH ─────────────────────────────────────────────────
def sign_in(email, password):
    try: return supabase.auth.sign_in_with_password({"email":email,"password":password}), None
    except Exception as e: return None, str(e)

def sign_up(email, password):
    try: return supabase.auth.sign_up({"email":email,"password":password}), None
    except Exception as e: return None, str(e)

def sign_out():
    supabase.auth.sign_out()
    st.session_state.clear()
    st.rerun()

# ── PAGE AUTH ────────────────────────────────────────────
def show_auth():
    st.markdown("""
    <div style="text-align:center;padding:80px 0 48px;">
      <div style="font-family:'Share Tech Mono',monospace;color:#00ff88;font-size:10px;letter-spacing:0.25em;margin-bottom:20px;opacity:0.8;">
        // CYBERSAAS · SECURE ACCESS PORTAL
      </div>
      <h1 style="font-size:52px;font-weight:800;margin-bottom:12px;line-height:1;">
        Cyber<span style="color:#00ff88;">SaaS</span>
      </h1>
      <p style="color:#5a5e6e;font-size:13px;font-family:'Share Tech Mono',monospace;margin-bottom:4px;">
        Audit de securite automatise pour PME
      </p>
      <p style="color:#3a3d4e;font-size:11px;font-family:'Share Tech Mono',monospace;">
        Reseau · Azure AD · IA · Conformite · Dashboard
      </p>
    </div>
    """, unsafe_allow_html=True)

    _, col, _ = st.columns([1,1.1,1])
    with col:
        st.markdown("""<div style="background:#0d0f14;border:1px solid rgba(0,255,136,0.1);padding:32px;">""", unsafe_allow_html=True)
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
                    with st.spinner(""):
                        res, err = sign_in(email, password)
                    if err: st.error(f"Erreur : {err}")
                    else:
                        st.session_state.user = res.user
                        st.session_state.logged_in = True
                        st.rerun()
                else: st.warning("Remplis tous les champs.")
        else:
            if st.button("Creer mon compte", use_container_width=True, type="primary"):
                if email and password:
                    if len(password) < 8: st.warning("8 caracteres minimum.")
                    else:
                        with st.spinner(""): res, err = sign_up(email, password)
                        if err: st.error(f"Erreur : {err}")
                        else:
                            st.success("Compte cree ! Verifie ton email.")
                            st.session_state.auth_mode = "login"
                else: st.warning("Remplis tous les champs.")
        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown("""<div style="text-align:center;margin-top:20px;font-size:10px;color:#2a2d3e;font-family:'Share Tech Mono',monospace;">
          100% gratuit · Aucune CB · RGPD compliant</div>""", unsafe_allow_html=True)

# ── APP PRINCIPALE ────────────────────────────────────────
def show_app():
    user = st.session_state.get("user")

    # Header
    c1, c2 = st.columns([6,1])
    with c1:
        st.markdown("""<div style="padding:12px 0 28px;display:flex;align-items:center;gap:16px;">
          <span style="font-family:'Syne',sans-serif;font-size:20px;font-weight:800;">
            Cyber<span style="color:#00ff88;">SaaS</span></span>
          <span style="font-family:'Share Tech Mono',monospace;font-size:9px;color:#00ff88;
            background:rgba(0,255,136,0.08);border:1px solid rgba(0,255,136,0.15);padding:3px 10px;letter-spacing:0.1em;">
            v3 · GRATUIT</span>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"<div style='text-align:right;padding-top:16px;font-size:10px;color:#3a3d4e;font-family:Share Tech Mono,monospace;'>{user.email if user else ''}</div>", unsafe_allow_html=True)
        if st.button("Exit", key="logout"):
            sign_out()

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "// RESEAU", "// AZURE AD", "// ANALYSE IA", "// DASHBOARD", "// RAPPORT"
    ])

    # ── TAB 1 : RESEAU ────────────────────────────────────
    with tab1:
        st.markdown("### Scan reseau automatise")
        st.markdown("<span style='font-family:Share Tech Mono,monospace;font-size:11px;color:#5a5e6e;'>Ports ouverts · Certificat SSL · Services exposes</span>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)
        c1, c2 = st.columns([4,1])
        with c1:
            target = st.text_input("", placeholder="monentreprise.fr ou 192.168.1.1", label_visibility="collapsed", key="net_target")
        with c2:
            go = st.button("Lancer le scan", type="primary", use_container_width=True)
        if go and target:
            with st.spinner(f"Analyse de {target} en cours..."):
                st.session_state["network_result"] = run_network_scan(target)
        if "network_result" in st.session_state:
            r = st.session_state["network_result"]
            st.divider()
            danger = sum(1 for p in r.open_ports if p.risk=="critical")
            ssl_ok = r.ssl and r.ssl.valid
            c1,c2,c3 = st.columns(3)
            with c1: st.markdown(card("SCORE RESEAU", r.score, "/100", sc(r.score)), unsafe_allow_html=True)
            with c2: st.markdown(card("PORTS DANGEREUX", danger, "detectes", "#ff4757" if danger>0 else "#00ff88"), unsafe_allow_html=True)
            with c3: st.markdown(card("SSL", "OK" if ssl_ok else "KO", r.ssl.message if r.ssl else "-", "#00ff88" if ssl_ok else "#ff4757"), unsafe_allow_html=True)
            st.markdown("<br>", unsafe_allow_html=True)
            findings_html = "".join(finding_row(f) for f in r.findings)
            st.markdown(f"<div style='margin-bottom:16px;'>{findings_html}</div>", unsafe_allow_html=True)
            if r.recommendations:
                recos_html = "".join(reco_row(r) for r in r.recommendations)
                st.markdown(recos_html, unsafe_allow_html=True)

    # ── TAB 2 : AZURE AD ──────────────────────────────────
    with tab2:
        st.markdown("### Scan Azure AD / Active Directory")
        st.markdown("<span style='font-family:Share Tech Mono,monospace;font-size:11px;color:#5a5e6e;'>MFA · Comptes inactifs · Admins · Policies · Appareils</span>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

        c1, c2 = st.columns([3,1])
        with c1:
            company_ad = st.text_input("Nom de l'entreprise a auditer", placeholder="ACME SAS", key="ad_company")
        with c2:
            st.markdown("<br>", unsafe_allow_html=True)
            scan_ad = st.button("Scanner Azure AD", type="primary", use_container_width=True)

        st.markdown("""<div style="background:rgba(61,139,255,0.06);border:1px solid rgba(61,139,255,0.15);
            padding:12px 16px;font-family:'Share Tech Mono',monospace;font-size:11px;color:#6b9fff;margin-top:8px;">
          Mode demo : donnees simulees realistes · Connectez votre vrai tenant via OAuth dans la version Pro
        </div>""", unsafe_allow_html=True)

        if scan_ad and company_ad:
            with st.spinner("Connexion Azure AD et analyse en cours..."):
                time.sleep(1.5)
                tenant = generate_fake_tenant(company_ad)
                result = analyze_azure_ad(tenant)
                st.session_state["ad_result"] = result
                st.session_state["ad_tenant"] = tenant

        if "ad_result" in st.session_state:
            r = st.session_state["ad_result"]
            tenant = st.session_state["ad_tenant"]
            st.divider()

            # Scores
            c1,c2,c3,c4 = st.columns(4)
            with c1: st.markdown(card("SCORE ACCES", r.score, "/100", sc(r.score)), unsafe_allow_html=True)
            with c2: st.markdown(card("MFA ACTIVE", f"{r.mfa_enabled_pct}%", "des utilisateurs", sc(r.mfa_enabled_pct)), unsafe_allow_html=True)
            with c3: st.markdown(card("COMPTES INACTIFS", r.inactive_count, "a desactiver", "#ff4757" if r.inactive_count>3 else "#ffd32a"), unsafe_allow_html=True)
            with c4: st.markdown(card("ADMINS", r.admin_count, "comptes privilegies", "#ffd32a" if r.admin_count>3 else "#00ff88"), unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            col_left, col_right = st.columns(2)

            with col_left:
                st.markdown("#### Problemes detectes")
                findings_html = "".join(finding_row(f) for f in r.findings)
                st.markdown(findings_html, unsafe_allow_html=True)

                st.markdown("<br>#### Policies de securite", unsafe_allow_html=True)
                for policy, ok in r.policy_results.items():
                    icon = "✓" if ok else "✗"
                    color = "#00ff88" if ok else "#ff4757"
                    st.markdown(f"<div style='font-family:Share Tech Mono,monospace;font-size:11px;padding:5px 0;color:{color};'>{icon} {policy}</div>", unsafe_allow_html=True)

            with col_right:
                st.markdown("#### Recommendations")
                recos_html = "".join(reco_row(r2) for r2 in r.recommendations)
                st.markdown(recos_html, unsafe_allow_html=True)

                if r.device_results:
                    st.markdown("<br>#### Appareils", unsafe_allow_html=True)
                    dr = r.device_results
                    st.markdown(f"""
                    <div style="background:#0d0f14;border:1px solid rgba(0,255,136,0.08);padding:16px;font-family:'Share Tech Mono',monospace;font-size:11px;">
                      <div style="margin-bottom:6px;color:#5a5e6e;">Total appareils : <span style="color:#e0e2ea;">{dr['total']}</span></div>
                      <div style="margin-bottom:6px;color:#5a5e6e;">Conformes : <span style="color:{sc(dr['compliant_pct'])};">{dr['compliant_pct']}%</span></div>
                      <div style="margin-bottom:6px;color:#5a5e6e;">BitLocker : <span style="color:{sc(dr['bitlocker_pct'])};">{dr['bitlocker_pct']}%</span></div>
                      <div style="color:#5a5e6e;">Geres : <span style="color:{sc(dr['managed_pct'])};">{dr['managed_pct']}%</span></div>
                    </div>""", unsafe_allow_html=True)

            if r.risky_users:
                st.markdown("<br>#### Utilisateurs a risque", unsafe_allow_html=True)
                for u in r.risky_users[:5]:
                    st.markdown(f"""
                    <div style="background:#0d0f14;border:1px solid rgba(255,71,87,0.15);padding:12px 16px;
                         margin-bottom:4px;border-left:2px solid #ff4757;font-family:'Share Tech Mono',monospace;font-size:11px;">
                      <span style="color:#ff4757;">CRITIQUE</span>
                      <span style="color:#e0e2ea;margin-left:12px;">{u.name}</span>
                      <span style="color:#5a5e6e;margin-left:8px;">{u.email}</span>
                      <span style="color:#ff4757;margin-left:12px;">· {', '.join(u.risks)}</span>
                    </div>""", unsafe_allow_html=True)

    # ── TAB 3 : ANALYSE IA ────────────────────────────────
    with tab3:
        st.markdown("### Analyse IA de fichiers")
        st.markdown("<span style='font-family:Share Tech Mono,monospace;font-size:11px;color:#5a5e6e;'>Upload logs / config firewall / exports AD / rapports d'audit → analyse automatique par IA</span>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

        api_key = st.text_input("Cle API Anthropic", type="password",
                                 placeholder="sk-ant-...",
                                 help="Obtiens ta cle sur console.anthropic.com · Reste confidentielle")

        uploaded = st.file_uploader(
            "Depose ton fichier ici",
            type=["txt","log","csv","json","conf","cfg","xml","ini"],
            help="Logs systeme, config firewall, export AD, rapport audit..."
        )

        if uploaded and api_key:
            if st.button("Analyser avec l'IA", type="primary"):
                content = uploaded.read().decode("utf-8", errors="ignore")
                with st.spinner(f"Analyse IA de {uploaded.name} en cours..."):
                    result = analyze_file_sync(content, uploaded.name, api_key)
                    st.session_state["ai_result"] = result

        elif uploaded and not api_key:
            st.warning("Entre ta cle API Anthropic pour lancer l'analyse.")

        if "ai_result" in st.session_state:
            r = st.session_state["ai_result"]
            st.divider()

            c1, c2 = st.columns([1,3])
            with c1:
                st.markdown(card("SCORE IA", r.score, r.file_type, sc(r.score)), unsafe_allow_html=True)
            with c2:
                st.markdown(f"""<div style="background:#0d0f14;border:1px solid rgba(0,255,136,0.08);
                    padding:20px;height:100%;font-family:'Share Tech Mono',monospace;font-size:12px;color:#9ca3af;">
                  <div style="color:#00ff88;font-size:10px;letter-spacing:0.15em;margin-bottom:8px;">RESUME IA</div>
                  {r.summary}
                </div>""", unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            col_l, col_r = st.columns(2)
            with col_l:
                st.markdown("#### Problemes detectes")
                for f in r.findings:
                    st.markdown(finding_row(f"🔴 {f}"), unsafe_allow_html=True)
                if r.compliance_gaps:
                    st.markdown("<br>#### Ecarts de conformite", unsafe_allow_html=True)
                    for gap in r.compliance_gaps:
                        st.markdown(finding_row(f"🟡 {gap}"), unsafe_allow_html=True)
            with col_r:
                st.markdown("#### Recommandations")
                for rec in r.recommendations:
                    st.markdown(reco_row(rec), unsafe_allow_html=True)

    # ── TAB 4 : DASHBOARD ─────────────────────────────────
    with tab4:
        st.markdown("### Dashboard & Historique")
        st.markdown("<span style='font-family:Share Tech Mono,monospace;font-size:11px;color:#5a5e6e;'>Suivi de l'evolution de votre score de securite</span>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

        # Score global actuel
        has_n = "network_result" in st.session_state
        has_a = "ad_result" in st.session_state
        has_ai = "ai_result" in st.session_state

        scores_available = []
        if has_n: scores_available.append(st.session_state["network_result"].score)
        if has_a: scores_available.append(st.session_state["ad_result"].score)
        if has_ai: scores_available.append(st.session_state["ai_result"].score)

        if scores_available:
            global_score = sum(scores_available) // len(scores_available)
            st.markdown(f"""
            <div style="background:linear-gradient(135deg,rgba(0,255,136,0.05),rgba(61,139,255,0.05));
                 border:1px solid rgba(0,255,136,0.12);padding:32px;text-align:center;margin-bottom:32px;">
              <div style="font-family:'Share Tech Mono',monospace;font-size:10px;color:#5a5e6e;letter-spacing:0.2em;margin-bottom:12px;">
                SCORE GLOBAL ACTUEL
              </div>
              <div style="font-family:'Syne',sans-serif;font-size:72px;font-weight:800;color:{sc(global_score)};line-height:1;">
                {global_score}
              </div>
              <div style="font-family:'Share Tech Mono',monospace;font-size:12px;color:{sc(global_score)};margin-top:8px;">
                /100 · {sl(global_score)}
              </div>
            </div>""", unsafe_allow_html=True)

            c1,c2,c3 = st.columns(3)
            with c1: st.markdown(card("RESEAU", st.session_state["network_result"].score if has_n else "N/A", "scan reseau", sc(st.session_state["network_result"].score) if has_n else "#3a3d4e"), unsafe_allow_html=True)
            with c2: st.markdown(card("AZURE AD", st.session_state["ad_result"].score if has_a else "N/A", "acces & identites", sc(st.session_state["ad_result"].score) if has_a else "#3a3d4e"), unsafe_allow_html=True)
            with c3: st.markdown(card("ANALYSE IA", st.session_state["ai_result"].score if has_ai else "N/A", "fichiers audites", sc(st.session_state["ai_result"].score) if has_ai else "#3a3d4e"), unsafe_allow_html=True)

            # Sauvegarder le scan
            st.markdown("<br>", unsafe_allow_html=True)
            company_save = st.text_input("Nom de l'entreprise pour sauvegarder", placeholder="ACME SAS", key="save_company")
            if st.button("Sauvegarder ce scan", type="primary") and company_save:
                scores = {
                    "global": global_score,
                    "network": st.session_state["network_result"].score if has_n else 0,
                    "access": st.session_state["ad_result"].score if has_a else 0,
                    "compliance": st.session_state["ai_result"].score if has_ai else 0,
                }
                findings = {
                    "network": st.session_state["network_result"].findings if has_n else [],
                    "access": st.session_state["ad_result"].findings if has_a else [],
                }
                ok = save_scan(supabase, user.id, company_save, scores, findings)
                if ok: st.success("Scan sauvegarde !")
                else: st.info("Sauvegarde : cree la table 'scans' dans Supabase pour activer l'historique.")

        else:
            st.markdown("""<div style="text-align:center;padding:60px;font-family:'Share Tech Mono',monospace;color:#3a3d4e;font-size:13px;">
              Lance au moins un scan pour voir ton dashboard
            </div>""", unsafe_allow_html=True)

        # Historique
        st.markdown("<br>#### Historique des scans", unsafe_allow_html=True)
        history = get_scan_history(supabase, user.id if user else "")
        if history:
            for scan in history:
                score_g = scan.get("score_global", 0)
                st.markdown(f"""
                <div style="background:#0d0f14;border:1px solid rgba(0,255,136,0.08);padding:14px 20px;
                     margin-bottom:4px;display:flex;align-items:center;gap:24px;font-family:'Share Tech Mono',monospace;font-size:11px;">
                  <span style="color:{sc(score_g)};font-family:'Syne',sans-serif;font-size:20px;font-weight:800;min-width:40px;">{score_g}</span>
                  <span style="color:#e0e2ea;flex:1;">{scan.get('company_name','')}</span>
                  <span style="color:#5a5e6e;">{scan.get('scanned_at','')[:10]}</span>
                  <span style="color:#5a5e6e;">Reseau: {scan.get('score_network',0)} · AD: {scan.get('score_access',0)}</span>
                </div>""", unsafe_allow_html=True)
        else:
            st.markdown("<span style='font-family:Share Tech Mono,monospace;font-size:11px;color:#3a3d4e;'>Aucun scan sauvegarde pour l'instant.</span>", unsafe_allow_html=True)

    # ── TAB 5 : RAPPORT ───────────────────────────────────
    with tab5:
        st.markdown("### Generer le rapport")
        st.markdown("<span style='font-family:Share Tech Mono,monospace;font-size:11px;color:#5a5e6e;'>Rapport professionnel PDF pour vos clients ou auditeurs</span>", unsafe_allow_html=True)
        st.markdown("<br>", unsafe_allow_html=True)

        company_r = st.text_input("Nom de l'entreprise", placeholder="ACME SAS", key="report_company")

        has_n = "network_result" in st.session_state
        has_acc = "access_result" in st.session_state
        has_c = "compliance_result" in st.session_state

        st.markdown(f"""<div style="display:flex;gap:20px;margin:16px 0;font-family:'Share Tech Mono',monospace;font-size:11px;">
          <span style="color:{'#00ff88' if has_n else '#3a3d4e'};">{'✓' if has_n else '○'} Reseau</span>
          <span style="color:{'#00ff88' if has_acc else '#3a3d4e'};">{'✓' if has_acc else '○'} Acces</span>
          <span style="color:{'#00ff88' if has_c else '#3a3d4e'};">{'✓' if has_c else '○'} Conformite</span>
        </div>""", unsafe_allow_html=True)

        if not all([has_n, has_acc, has_c]):
            st.markdown("""<div style="background:rgba(255,183,0,0.06);border:1px solid rgba(255,183,0,0.15);
                padding:12px 16px;font-family:'Share Tech Mono',monospace;font-size:11px;color:#ffd32a;">
              Lance les modules Reseau + Acces + Conformite pour generer le rapport complet.
            </div>""", unsafe_allow_html=True)

        if st.button("Generer le rapport", type="primary", disabled=not company_r):
            if not all([has_n, has_acc, has_c]):
                st.warning("Complete les modules Reseau, Acces et Conformite.")
            else:
                with st.spinner("Generation en cours..."):
                    html = generate_html_report(
                        company_name=company_r,
                        network=st.session_state["network_result"],
                        access=st.session_state["access_result"],
                        compliance=st.session_state["compliance_result"],
                    )
                st.download_button("Telecharger le rapport", data=html,
                    file_name=f"rapport_{company_r.lower().replace(' ','_')}.html", mime="text/html")
                st.success("Rapport pret ! Ouvre dans le navigateur et imprime en PDF.")

# ── ROUTING ──────────────────────────────────────────────
if not st.session_state.get("logged_in"):
    show_auth()
else:
    show_app()
