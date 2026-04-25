"""CyberSaaS v4 — Dashboard avec graphiques Plotly"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import time
import json
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
@import url('https://fonts.googleapis.com/css2?family=Syne:wght@700;800&family=Share+Tech+Mono&family=DM+Sans:wght@300;400;500&display=swap');
html,body,.stApp{background:#050507 !important;color:#e0e2ea;}
h1,h2,h3{font-family:'Syne',sans-serif !important;letter-spacing:-0.02em;}
p,span,div{font-family:'DM Sans',sans-serif;}
.stTextInput input,.stTextArea textarea{background:#0d0f14 !important;border:1px solid rgba(0,255,136,0.15) !important;color:#e0e2ea !important;border-radius:4px !important;}
.stTextInput input:focus{border-color:rgba(0,255,136,0.5) !important;box-shadow:0 0 0 2px rgba(0,255,136,0.1) !important;}
.stButton>button{background:#00ff88 !important;color:#050507 !important;border:none !important;font-family:'Syne',sans-serif !important;font-weight:700 !important;border-radius:4px !important;transition:all 0.2s !important;padding:10px 24px !important;}
.stButton>button:hover{background:#00cc6a !important;box-shadow:0 4px 20px rgba(0,255,136,0.3) !important;transform:translateY(-1px) !important;}
.stTabs [data-baseweb="tab-list"]{background:#0a0c10 !important;border-bottom:1px solid rgba(0,255,136,0.08) !important;gap:4px !important;padding:0 8px !important;}
.stTabs [data-baseweb="tab"]{background:transparent !important;color:#5a5e6e !important;font-family:'Share Tech Mono',monospace !important;font-size:11px !important;letter-spacing:0.08em !important;padding:12px 20px !important;border-radius:4px 4px 0 0 !important;}
.stTabs [aria-selected="true"]{color:#00ff88 !important;background:rgba(0,255,136,0.06) !important;border-bottom:2px solid #00ff88 !important;}
.stFileUploader{background:#0d0f14 !important;border:1px dashed rgba(0,255,136,0.2) !important;border-radius:4px !important;}
.stExpander{background:#0d0f14 !important;border:1px solid rgba(255,255,255,0.05) !important;border-radius:4px !important;}
.stRadio>div{gap:8px !important;}
.stRadio label{font-size:13px !important;}
hr{border-color:rgba(0,255,136,0.08) !important;}
[data-testid="stSidebar"]{display:none;}
::-webkit-scrollbar{width:4px;}::-webkit-scrollbar-thumb{background:rgba(0,255,136,0.2);border-radius:2px;}
.element-container{animation:fadeIn 0.3s ease;}
@keyframes fadeIn{from{opacity:0;transform:translateY(8px);}to{opacity:1;transform:translateY(0);}}
</style>
""", unsafe_allow_html=True)

# ── PLOTLY THEME ─────────────────────────────────────────
PLOT_BG = "rgba(0,0,0,0)"
PAPER_BG = "rgba(13,15,20,1)"
GRID_COLOR = "rgba(255,255,255,0.04)"
FONT_COLOR = "#9ca3af"
GREEN = "#00ff88"
YELLOW = "#ffd32a"
RED = "#ff4757"
BLUE = "#3d8bff"
PURPLE = "#a78bfa"

def plot_config():
    return {"displayModeBar": False, "responsive": True}

def gauge_chart(value, title, color=None):
    if color is None:
        color = GREEN if value >= 80 else YELLOW if value >= 50 else RED
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        domain={"x":[0,1],"y":[0,1]},
        title={"text": title, "font": {"size":13, "color": FONT_COLOR, "family":"Share Tech Mono"}},
        number={"font":{"size":48,"color":color,"family":"Syne"},"suffix":"/100"},
        gauge={
            "axis":{"range":[0,100],"tickcolor":GRID_COLOR,"tickfont":{"color":FONT_COLOR,"size":10}},
            "bar":{"color":color,"thickness":0.25},
            "bgcolor":"rgba(255,255,255,0.04)",
            "borderwidth":0,
            "steps":[
                {"range":[0,50],"color":"rgba(255,71,87,0.06)"},
                {"range":[50,80],"color":"rgba(255,211,42,0.06)"},
                {"range":[80,100],"color":"rgba(0,255,136,0.06)"},
            ],
            "threshold":{"line":{"color":color,"width":2},"thickness":0.8,"value":value}
        }
    ))
    fig.update_layout(
        paper_bgcolor=PAPER_BG, plot_bgcolor=PLOT_BG,
        margin=dict(l=20,r=20,t=40,b=20), height=220,
        font=dict(family="DM Sans")
    )
    return fig

def donut_chart(values, labels, colors, title):
    fig = go.Figure(go.Pie(
        values=values, labels=labels,
        hole=0.65,
        marker=dict(colors=colors, line=dict(color=PAPER_BG, width=2)),
        textinfo="none",
        hovertemplate="%{label}: %{value}<extra></extra>"
    ))
    fig.update_layout(
        paper_bgcolor=PAPER_BG, plot_bgcolor=PLOT_BG,
        margin=dict(l=10,r=10,t=40,b=10), height=220,
        title=dict(text=title, font=dict(size=12,color=FONT_COLOR,family="Share Tech Mono"),x=0.5),
        showlegend=True,
        legend=dict(font=dict(color=FONT_COLOR,size=11),bgcolor="rgba(0,0,0,0)",orientation="h",y=-0.1),
        font=dict(family="DM Sans")
    )
    return fig

def bar_chart(categories, values, colors, title):
    fig = go.Figure(go.Bar(
        x=categories, y=values,
        marker=dict(color=colors, line=dict(width=0)),
        text=values, textposition="outside",
        textfont=dict(color=FONT_COLOR, size=11),
        hovertemplate="%{x}: %{y}/100<extra></extra>"
    ))
    fig.update_layout(
        paper_bgcolor=PAPER_BG, plot_bgcolor=PLOT_BG,
        margin=dict(l=10,r=10,t=40,b=10), height=240,
        title=dict(text=title, font=dict(size=12,color=FONT_COLOR,family="Share Tech Mono"),x=0),
        xaxis=dict(tickfont=dict(color=FONT_COLOR,size=11),gridcolor=GRID_COLOR,showgrid=False),
        yaxis=dict(tickfont=dict(color=FONT_COLOR,size=10),gridcolor=GRID_COLOR,range=[0,115]),
        font=dict(family="DM Sans")
    )
    return fig

def radar_chart(categories, values, title):
    fig = go.Figure(go.Scatterpolar(
        r=values + [values[0]],
        theta=categories + [categories[0]],
        fill="toself",
        fillcolor="rgba(0,255,136,0.08)",
        line=dict(color=GREEN, width=2),
        marker=dict(color=GREEN, size=6),
        hovertemplate="%{theta}: %{r}/100<extra></extra>"
    ))
    fig.update_layout(
        paper_bgcolor=PAPER_BG, plot_bgcolor=PLOT_BG,
        polar=dict(
            bgcolor=PAPER_BG,
            radialaxis=dict(visible=True, range=[0,100], tickfont=dict(color=FONT_COLOR,size=9), gridcolor=GRID_COLOR),
            angularaxis=dict(tickfont=dict(color=FONT_COLOR,size=11), gridcolor=GRID_COLOR)
        ),
        margin=dict(l=40,r=40,t=50,b=40), height=300,
        title=dict(text=title, font=dict(size=12,color=FONT_COLOR,family="Share Tech Mono"),x=0.5),
        font=dict(family="DM Sans"),
        showlegend=False
    )
    return fig

def history_line_chart(history):
    if not history: return None
    dates = [s.get("scanned_at","")[:10] for s in reversed(history)]
    scores = [s.get("score_global",0) for s in reversed(history)]
    colors_pts = [GREEN if s>=80 else YELLOW if s>=50 else RED for s in scores]
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=dates, y=scores,
        mode="lines+markers",
        line=dict(color=GREEN, width=2),
        marker=dict(color=colors_pts, size=8, line=dict(color=PAPER_BG,width=2)),
        fill="tozeroy", fillcolor="rgba(0,255,136,0.04)",
        hovertemplate="%{x}: %{y}/100<extra></extra>"
    ))
    fig.update_layout(
        paper_bgcolor=PAPER_BG, plot_bgcolor=PLOT_BG,
        margin=dict(l=10,r=10,t=40,b=10), height=220,
        title=dict(text="EVOLUTION DU SCORE", font=dict(size=12,color=FONT_COLOR,family="Share Tech Mono"),x=0),
        xaxis=dict(tickfont=dict(color=FONT_COLOR,size=10), gridcolor=GRID_COLOR, showgrid=True),
        yaxis=dict(tickfont=dict(color=FONT_COLOR,size=10), gridcolor=GRID_COLOR, range=[0,105]),
        font=dict(family="DM Sans")
    )
    return fig

# ── HELPERS ──────────────────────────────────────────────
def sc(s):
    if s>=80: return GREEN
    if s>=50: return YELLOW
    return RED

def sl(s):
    if s>=80: return "Bon"
    if s>=50: return "A ameliorer"
    return "Critique"

def metric_card(label, value, sub, color, icon=""):
    return f"""<div style="background:#0d0f14;border:1px solid rgba(255,255,255,0.05);
        padding:20px 24px;border-radius:8px;border-left:3px solid {color};">
      <div style="font-size:10px;color:#5a5e6e;letter-spacing:0.15em;text-transform:uppercase;
           margin-bottom:8px;font-family:'Share Tech Mono',monospace;">{icon} {label}</div>
      <div style="font-family:'Syne',sans-serif;font-size:28px;font-weight:800;color:{color};line-height:1;">{value}</div>
      <div style="font-size:11px;color:#5a5e6e;margin-top:6px;">{sub}</div>
    </div>"""

def finding_card(text, severity="medium"):
    colors = {"critical": RED, "high": "#ff8c00", "medium": YELLOW, "ok": GREEN}
    color = colors.get(severity, YELLOW)
    return f"""<div style="background:#0d0f14;border:1px solid rgba(255,255,255,0.04);
        padding:12px 16px;border-radius:4px;border-left:3px solid {color};
        margin-bottom:6px;font-family:'DM Sans',sans-serif;font-size:13px;line-height:1.5;">
      {text}
    </div>"""

def reco_card(text):
    return f"""<div style="background:rgba(61,139,255,0.05);border:1px solid rgba(61,139,255,0.12);
        padding:12px 16px;border-radius:4px;border-left:3px solid {BLUE};
        margin-bottom:6px;font-family:'DM Sans',sans-serif;font-size:13px;color:#9ca3af;line-height:1.5;">
      <span style="color:{BLUE};">→</span> {text}
    </div>"""

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
      <div style="font-family:'Share Tech Mono',monospace;color:#00ff88;font-size:10px;
           letter-spacing:0.25em;margin-bottom:20px;opacity:0.7;">
        // CYBERSAAS · SECURE ACCESS
      </div>
      <h1 style="font-size:52px;font-weight:800;margin-bottom:12px;line-height:1;">
        Cyber<span style="color:#00ff88;">SaaS</span>
      </h1>
      <p style="color:#5a5e6e;font-size:14px;font-family:'DM Sans',sans-serif;font-weight:300;">
        Audit de securite automatise · Dashboard · Rapports
      </p>
    </div>
    """, unsafe_allow_html=True)

    _, col, _ = st.columns([1,1,1])
    with col:
        st.markdown("""<div style="background:#0d0f14;border:1px solid rgba(0,255,136,0.1);
            padding:40px;border-radius:8px;">""", unsafe_allow_html=True)

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
            if st.button("Se connecter →", use_container_width=True, type="primary"):
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
            if st.button("Creer mon compte →", use_container_width=True, type="primary"):
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
        st.markdown("""<div style="text-align:center;margin-top:16px;font-size:11px;
            color:#2a2d3e;font-family:'Share Tech Mono',monospace;letter-spacing:0.08em;">
          100% GRATUIT · AUCUNE CB · RGPD</div>""", unsafe_allow_html=True)

# ── APP PRINCIPALE ────────────────────────────────────────
def show_app():
    user = st.session_state.get("user")

    # Header
    c1, c2, c3 = st.columns([4,2,1])
    with c1:
        st.markdown("""<div style="padding:16px 0 32px;">
          <span style="font-family:'Syne',sans-serif;font-size:22px;font-weight:800;">
            Cyber<span style="color:#00ff88;">SaaS</span></span>
          <span style="font-family:'Share Tech Mono',monospace;font-size:9px;color:#00ff88;
            background:rgba(0,255,136,0.08);border:1px solid rgba(0,255,136,0.15);
            padding:3px 10px;margin-left:12px;border-radius:2px;letter-spacing:0.1em;">
            v4 · GRATUIT</span>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f"""<div style="text-align:right;padding-top:20px;font-size:11px;
            color:#3a3d4e;font-family:'Share Tech Mono',monospace;">
            {user.email if user else ''}</div>""", unsafe_allow_html=True)
    with c3:
        st.markdown("<div style='padding-top:12px;'>", unsafe_allow_html=True)
        if st.button("Deconnexion"):
            sign_out()
        st.markdown("</div>", unsafe_allow_html=True)

    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🌐 Reseau", "🔐 Azure AD", "🤖 Analyse IA", "📊 Dashboard", "📄 Rapport"
    ])

    # ── TAB 1 : RESEAU ────────────────────────────────────
    with tab1:
        st.markdown("### Scan reseau")
        st.markdown("<p style='color:#5a5e6e;font-size:13px;margin-bottom:24px;'>Analyse automatique des ports, services exposes et certificat SSL.</p>", unsafe_allow_html=True)

        c1, c2 = st.columns([4,1])
        with c1:
            target = st.text_input("", placeholder="monentreprise.fr ou 192.168.1.1", label_visibility="collapsed", key="net_target")
        with c2:
            go = st.button("Scanner →", type="primary", use_container_width=True)

        if go and target:
            with st.spinner(f"Analyse de {target}..."):
                st.session_state["network_result"] = run_network_scan(target)

        if "network_result" in st.session_state:
            r = st.session_state["network_result"]
            st.divider()
            danger = sum(1 for p in r.open_ports if p.risk=="critical")
            ssl_ok = r.ssl and r.ssl.valid

            # Gauge + metriques
            c1, c2, c3, c4 = st.columns([2,1,1,1])
            with c1:
                st.plotly_chart(gauge_chart(r.score, "SCORE RESEAU"), use_container_width=True, config=plot_config())
            with c2:
                st.markdown(metric_card("PORTS OUVERTS", len(r.open_ports), "detectes", BLUE, "🔌"), unsafe_allow_html=True)
            with c3:
                st.markdown(metric_card("DANGEREUX", danger, "ports critiques", RED if danger>0 else GREEN, "⚠️"), unsafe_allow_html=True)
            with c4:
                st.markdown(metric_card("SSL", "OK" if ssl_ok else "KO", r.ssl.message[:30] if r.ssl else "-", GREEN if ssl_ok else RED, "🔒"), unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            col_l, col_r = st.columns(2)
            with col_l:
                st.markdown("**Problemes detectes**")
                for f in r.findings:
                    sev = "critical" if "🔴" in f else "high" if "🟠" in f else "ok" if "✅" in f else "medium"
                    st.markdown(finding_card(f, sev), unsafe_allow_html=True)
            with col_r:
                if r.recommendations:
                    st.markdown("**Recommandations**")
                    for rec in r.recommendations:
                        st.markdown(reco_card(rec), unsafe_allow_html=True)

    # ── TAB 2 : AZURE AD ──────────────────────────────────
    with tab2:
        st.markdown("### Scan Azure AD / Active Directory")
        st.markdown("<p style='color:#5a5e6e;font-size:13px;margin-bottom:24px;'>MFA, comptes inactifs, admins exposes, policies et appareils.</p>", unsafe_allow_html=True)

        c1, c2 = st.columns([4,1])
        with c1:
            company_ad = st.text_input("", placeholder="Nom de l'entreprise (ex: ACME SAS)", label_visibility="collapsed", key="ad_company")
        with c2:
            scan_ad = st.button("Scanner →", type="primary", use_container_width=True, key="btn_ad")

        st.markdown("""<div style="background:rgba(61,139,255,0.04);border:1px solid rgba(61,139,255,0.1);
            padding:10px 16px;border-radius:4px;font-size:12px;color:#6b9fff;margin-top:8px;">
          Mode demo · Donnees simulees realistes · Connexion OAuth reelle disponible en Pro
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

            # Row 1 : Gauge + donuts
            c1, c2, c3 = st.columns(3)
            with c1:
                st.plotly_chart(gauge_chart(r.score, "SCORE ACCES"), use_container_width=True, config=plot_config())
            with c2:
                mfa_on = int(r.mfa_enabled_pct * r.total_users / 100)
                mfa_off = r.total_users - mfa_on
                st.plotly_chart(donut_chart(
                    [mfa_on, mfa_off], ["MFA actif", "Sans MFA"],
                    [GREEN, RED], "MFA UTILISATEURS"
                ), use_container_width=True, config=plot_config())
            with c3:
                active = r.total_users - r.inactive_count
                st.plotly_chart(donut_chart(
                    [active, r.inactive_count], ["Actifs", "Inactifs +90j"],
                    [BLUE, YELLOW], "COMPTES"
                ), use_container_width=True, config=plot_config())

            # Row 2 : Metriques
            c1,c2,c3,c4 = st.columns(4)
            with c1: st.markdown(metric_card("UTILISATEURS", r.total_users, "comptes totaux", BLUE, "👥"), unsafe_allow_html=True)
            with c2: st.markdown(metric_card("ADMINS", r.admin_count, "comptes privilegies", YELLOW if r.admin_count>3 else GREEN, "👑"), unsafe_allow_html=True)
            with c3: st.markdown(metric_card("INACTIFS", r.inactive_count, "a desactiver", RED if r.inactive_count>3 else YELLOW, "💤"), unsafe_allow_html=True)
            with c4: st.markdown(metric_card("MFA", f"{r.mfa_enabled_pct}%", "des utilisateurs", sc(r.mfa_enabled_pct), "🔑"), unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)

            # Row 3 : Policies bar + findings
            c_left, c_right = st.columns(2)
            with c_left:
                policy_names = list(r.policy_results.keys())
                policy_vals = [100 if v else 0 for v in r.policy_results.values()]
                policy_colors = [GREEN if v==100 else RED for v in policy_vals]
                st.plotly_chart(bar_chart(
                    [n[:20] for n in policy_names], policy_vals, policy_colors, "POLICIES DE SECURITE"
                ), use_container_width=True, config=plot_config())

            with c_right:
                st.markdown("**Problemes detectes**")
                for f in r.findings[:6]:
                    sev = "critical" if "🔴" in f else "high" if "🟠" in f else "ok" if "✅" in f else "medium"
                    st.markdown(finding_card(f, sev), unsafe_allow_html=True)

            # Recommandations
            if r.recommendations:
                st.markdown("**Recommandations prioritaires**")
                cols = st.columns(2)
                for i, rec in enumerate(r.recommendations[:6]):
                    with cols[i%2]:
                        st.markdown(reco_card(rec), unsafe_allow_html=True)

            # Utilisateurs a risque
            if r.risky_users:
                st.markdown("<br>**Utilisateurs a risque**", unsafe_allow_html=True)
                for u in r.risky_users[:4]:
                    st.markdown(f"""<div style="background:#0d0f14;border:1px solid rgba(255,71,87,0.12);
                        padding:12px 20px;border-radius:4px;border-left:3px solid {RED};
                        margin-bottom:4px;display:flex;align-items:center;gap:16px;font-size:13px;">
                      <span style="color:{RED};font-size:10px;letter-spacing:0.1em;font-family:Share Tech Mono,monospace;min-width:60px;">CRITIQUE</span>
                      <span style="font-weight:500;">{u.name}</span>
                      <span style="color:#5a5e6e;">{u.email}</span>
                      <span style="color:{RED};margin-left:auto;font-size:12px;">{', '.join(u.risks)}</span>
                    </div>""", unsafe_allow_html=True)

    # ── TAB 3 : ANALYSE IA ────────────────────────────────
    with tab3:
        st.markdown("### Analyse IA de fichiers")
        st.markdown("<p style='color:#5a5e6e;font-size:13px;margin-bottom:24px;'>Upload logs, config firewall, exports AD → analyse automatique par IA.</p>", unsafe_allow_html=True)

        c1, c2 = st.columns([2,1])
        with c1:
            api_key = st.text_input("Cle API Anthropic", type="password", placeholder="sk-ant-...", key="api_key")
        with c2:
            st.markdown("<div style='padding-top:4px;font-size:11px;color:#5a5e6e;'>Obtiens ta cle sur <a href='https://console.anthropic.com' target='_blank' style='color:#3d8bff;'>console.anthropic.com</a></div>", unsafe_allow_html=True)

        uploaded = st.file_uploader("", type=["txt","log","csv","json","conf","cfg","xml","ini"], label_visibility="collapsed")

        if uploaded and api_key:
            if st.button("Analyser avec l'IA →", type="primary"):
                content = uploaded.read().decode("utf-8", errors="ignore")
                with st.spinner(f"Analyse IA de {uploaded.name}..."):
                    result = analyze_file_sync(content, uploaded.name, api_key)
                    st.session_state["ai_result"] = result

        if "ai_result" in st.session_state:
            r = st.session_state["ai_result"]
            st.divider()

            c1, c2, c3 = st.columns(3)
            with c1:
                st.plotly_chart(gauge_chart(r.score, "SCORE IA"), use_container_width=True, config=plot_config())
            with c2:
                st.markdown(f"""<div style="background:#0d0f14;border:1px solid rgba(0,255,136,0.08);
                    padding:24px;border-radius:8px;height:100%;">
                  <div style="font-size:10px;color:#5a5e6e;letter-spacing:0.15em;text-transform:uppercase;
                       margin-bottom:12px;font-family:'Share Tech Mono',monospace;">TYPE DE FICHIER</div>
                  <div style="font-size:14px;font-weight:500;color:#00ff88;">{r.file_type}</div>
                  <div style="font-size:10px;color:#5a5e6e;letter-spacing:0.15em;text-transform:uppercase;
                       margin-top:20px;margin-bottom:8px;font-family:'Share Tech Mono',monospace;">RESUME</div>
                  <div style="font-size:13px;color:#9ca3af;line-height:1.6;">{r.summary}</div>
                </div>""", unsafe_allow_html=True)
            with c3:
                if r.compliance_gaps:
                    gap_count = len(r.compliance_gaps)
                    st.markdown(metric_card("ECARTS CONFORMITE", gap_count, "detectes", RED if gap_count>2 else YELLOW, "📋"), unsafe_allow_html=True)

            st.markdown("<br>", unsafe_allow_html=True)
            col_l, col_r = st.columns(2)
            with col_l:
                st.markdown("**Vulnerabilites detectees**")
                for f in r.findings:
                    st.markdown(finding_card(f"🔴 {f}", "critical"), unsafe_allow_html=True)
                if r.compliance_gaps:
                    st.markdown("<br>**Ecarts de conformite**", unsafe_allow_html=True)
                    for gap in r.compliance_gaps:
                        st.markdown(finding_card(f"🟡 {gap}", "medium"), unsafe_allow_html=True)
            with col_r:
                st.markdown("**Recommandations**")
                for rec in r.recommendations:
                    st.markdown(reco_card(rec), unsafe_allow_html=True)

    # ── TAB 4 : DASHBOARD ─────────────────────────────────
    with tab4:
        st.markdown("### Dashboard de securite")
        st.markdown("<p style='color:#5a5e6e;font-size:13px;margin-bottom:24px;'>Vue globale et evolution de votre score dans le temps.</p>", unsafe_allow_html=True)

        has_n = "network_result" in st.session_state
        has_a = "ad_result" in st.session_state
        has_ai = "ai_result" in st.session_state

        scores_available = []
        if has_n: scores_available.append(st.session_state["network_result"].score)
        if has_a: scores_available.append(st.session_state["ad_result"].score)
        if has_ai: scores_available.append(st.session_state["ai_result"].score)

        if scores_available:
            global_score = sum(scores_available) // len(scores_available)

            # Score global hero
            c1, c2 = st.columns([1,2])
            with c1:
                st.plotly_chart(gauge_chart(global_score, "SCORE GLOBAL"), use_container_width=True, config=plot_config())
            with c2:
                # Radar des modules
                cats = []
                vals = []
                if has_n: cats.append("Reseau"); vals.append(st.session_state["network_result"].score)
                if has_a: cats.append("Azure AD"); vals.append(st.session_state["ad_result"].score)
                if has_ai: cats.append("Analyse IA"); vals.append(st.session_state["ai_result"].score)
                if len(cats) >= 3:
                    st.plotly_chart(radar_chart(cats, vals, "PROFIL DE SECURITE"), use_container_width=True, config=plot_config())
                else:
                    # Bar chart si moins de 3 modules
                    colors = [sc(v) for v in vals]
                    st.plotly_chart(bar_chart(cats, vals, colors, "SCORES PAR MODULE"), use_container_width=True, config=plot_config())

            # Metriques
            c1,c2,c3 = st.columns(3)
            with c1: st.markdown(metric_card("RESEAU", st.session_state["network_result"].score if has_n else "—", "scan reseau", sc(st.session_state["network_result"].score) if has_n else "#3a3d4e", "🌐"), unsafe_allow_html=True)
            with c2: st.markdown(metric_card("AZURE AD", st.session_state["ad_result"].score if has_a else "—", "acces & identites", sc(st.session_state["ad_result"].score) if has_a else "#3a3d4e", "🔐"), unsafe_allow_html=True)
            with c3: st.markdown(metric_card("ANALYSE IA", st.session_state["ai_result"].score if has_ai else "—", "fichiers audites", sc(st.session_state["ai_result"].score) if has_ai else "#3a3d4e", "🤖"), unsafe_allow_html=True)

            # Sauvegarder
            st.markdown("<br>", unsafe_allow_html=True)
            c1, c2 = st.columns([3,1])
            with c1:
                company_save = st.text_input("", placeholder="Nom de l'entreprise pour sauvegarder ce scan", label_visibility="collapsed", key="save_company")
            with c2:
                if st.button("Sauvegarder →", type="primary", use_container_width=True):
                    if company_save:
                        scores = {"global":global_score, "network": st.session_state["network_result"].score if has_n else 0, "access": st.session_state["ad_result"].score if has_a else 0, "compliance": st.session_state["ai_result"].score if has_ai else 0}
                        findings = {"network": st.session_state["network_result"].findings if has_n else [], "access": st.session_state["ad_result"].findings if has_a else []}
                        ok = save_scan(supabase, user.id, company_save, scores, findings)
                        if ok: st.success("Scan sauvegarde !")
                        else: st.info("Cree la table 'scans' dans Supabase pour activer l'historique.")

        else:
            st.markdown("""<div style="text-align:center;padding:80px;background:#0d0f14;
                border:1px solid rgba(255,255,255,0.04);border-radius:8px;">
              <div style="font-size:48px;margin-bottom:16px;">📊</div>
              <div style="font-family:'Syne',sans-serif;font-size:20px;font-weight:700;margin-bottom:8px;">Dashboard vide</div>
              <div style="color:#5a5e6e;font-size:13px;">Lance les modules Reseau et Azure AD pour voir ton dashboard.</div>
            </div>""", unsafe_allow_html=True)

        # Historique
        st.markdown("<br>", unsafe_allow_html=True)
        history = get_scan_history(supabase, user.id if user else "")
        if history:
            st.markdown("**Historique des scans**")
            hist_chart = history_line_chart(history)
            if hist_chart:
                st.plotly_chart(hist_chart, use_container_width=True, config=plot_config())
            for scan in history[:5]:
                score_g = scan.get("score_global",0)
                st.markdown(f"""<div style="background:#0d0f14;border:1px solid rgba(255,255,255,0.04);
                    padding:14px 20px;border-radius:4px;margin-bottom:4px;
                    display:flex;align-items:center;gap:24px;font-size:13px;">
                  <span style="color:{sc(score_g)};font-family:'Syne',sans-serif;font-size:22px;font-weight:800;min-width:44px;">{score_g}</span>
                  <span style="font-weight:500;flex:1;">{scan.get('company_name','')}</span>
                  <span style="color:#5a5e6e;font-family:'Share Tech Mono',monospace;font-size:11px;">{scan.get('scanned_at','')[:10]}</span>
                </div>""", unsafe_allow_html=True)

    # ── TAB 5 : RAPPORT ───────────────────────────────────
    with tab5:
        st.markdown("### Generer le rapport")
        st.markdown("<p style='color:#5a5e6e;font-size:13px;margin-bottom:24px;'>Rapport professionnel PDF pour vos clients ou auditeurs.</p>", unsafe_allow_html=True)

        has_n = "network_result" in st.session_state
        has_acc = "access_result" in st.session_state
        has_c = "compliance_result" in st.session_state

        c1, c2 = st.columns([3,1])
        with c1:
            company_r = st.text_input("", placeholder="Nom de l'entreprise", label_visibility="collapsed", key="report_company")
        with c2:
            if st.button("Generer →", type="primary", use_container_width=True, disabled=not company_r):
                if not all([has_n, has_acc, has_c]):
                    st.warning("Complete les modules Reseau, Acces et Conformite.")
                else:
                    with st.spinner("Generation du rapport..."):
                        html = generate_html_report(
                            company_name=company_r,
                            network=st.session_state["network_result"],
                            access=st.session_state["access_result"],
                            compliance=st.session_state["compliance_result"],
                        )
                    st.download_button("Telecharger le rapport HTML", data=html,
                        file_name=f"rapport_{company_r.lower().replace(' ','_')}.html", mime="text/html")
                    st.success("Ouvre dans le navigateur et imprime en PDF.")

        st.markdown(f"""<div style="display:flex;gap:12px;margin-top:20px;flex-wrap:wrap;">
          <div style="background:#0d0f14;border:1px solid rgba(255,255,255,0.04);padding:12px 20px;border-radius:4px;
               border-left:3px solid {'#00ff88' if has_n else '#3a3d4e'};font-size:13px;">
            {'✓' if has_n else '○'} Reseau</div>
          <div style="background:#0d0f14;border:1px solid rgba(255,255,255,0.04);padding:12px 20px;border-radius:4px;
               border-left:3px solid {'#00ff88' if has_acc else '#3a3d4e'};font-size:13px;">
            {'✓' if has_acc else '○'} Acces</div>
          <div style="background:#0d0f14;border:1px solid rgba(255,255,255,0.04);padding:12px 20px;border-radius:4px;
               border-left:3px solid {'#00ff88' if has_c else '#3a3d4e'};font-size:13px;">
            {'✓' if has_c else '○'} Conformite</div>
        </div>""", unsafe_allow_html=True)

# ── ROUTING ──────────────────────────────────────────────
if not st.session_state.get("logged_in"):
    show_auth()
else:
    show_app()
