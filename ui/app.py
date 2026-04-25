"""CyberSaaS v5 — Design premium Vercel/Linear"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import streamlit as st
import plotly.graph_objects as go
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
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

html, body, .stApp {
  background: #09090b !important;
  color: #fafafa;
  font-family: 'Inter', -apple-system, sans-serif;
  -webkit-font-smoothing: antialiased;
}

/* Remove streamlit padding */
.block-container { padding: 32px 40px !important; max-width: 1200px !important; }
.stApp > header { display: none; }

/* Typography */
h1, h2, h3, h4 {
  font-family: 'Inter', sans-serif !important;
  font-weight: 600 !important;
  letter-spacing: -0.025em !important;
  color: #fafafa !important;
}

/* Inputs */
.stTextInput input, .stTextArea textarea {
  background: #18181b !important;
  border: 1px solid #27272a !important;
  color: #fafafa !important;
  font-family: 'Inter', sans-serif !important;
  font-size: 14px !important;
  border-radius: 8px !important;
  padding: 10px 14px !important;
  transition: border-color 0.15s !important;
}
.stTextInput input:focus, .stTextArea textarea:focus {
  border-color: #52525b !important;
  box-shadow: 0 0 0 3px rgba(255,255,255,0.06) !important;
  outline: none !important;
}
.stTextInput input::placeholder { color: #52525b !important; }

/* Buttons */
.stButton > button {
  background: #fafafa !important;
  color: #09090b !important;
  border: none !important;
  font-family: 'Inter', sans-serif !important;
  font-weight: 600 !important;
  font-size: 13px !important;
  border-radius: 8px !important;
  padding: 10px 20px !important;
  transition: all 0.15s !important;
  letter-spacing: -0.01em !important;
}
.stButton > button:hover {
  background: #e4e4e7 !important;
  transform: translateY(-1px) !important;
  box-shadow: 0 4px 12px rgba(0,0,0,0.4) !important;
}

/* Tabs */
.stTabs [data-baseweb="tab-list"] {
  background: transparent !important;
  border-bottom: 1px solid #27272a !important;
  gap: 0 !important;
  padding: 0 !important;
}
.stTabs [data-baseweb="tab"] {
  background: transparent !important;
  color: #71717a !important;
  font-family: 'Inter', sans-serif !important;
  font-size: 13px !important;
  font-weight: 500 !important;
  padding: 12px 20px !important;
  border-bottom: 2px solid transparent !important;
  transition: all 0.15s !important;
}
.stTabs [data-baseweb="tab"]:hover { color: #a1a1aa !important; }
.stTabs [aria-selected="true"] {
  color: #fafafa !important;
  border-bottom: 2px solid #fafafa !important;
  background: transparent !important;
}

/* File uploader */
.stFileUploader {
  background: #18181b !important;
  border: 1px dashed #27272a !important;
  border-radius: 8px !important;
}

/* Radio */
.stRadio label { font-size: 13px !important; color: #a1a1aa !important; }

/* Divider */
hr { border-color: #27272a !important; margin: 24px 0 !important; }

/* Sidebar */
[data-testid="stSidebar"] { display: none !important; }

/* Scrollbar */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: #27272a; border-radius: 4px; }

/* Spinner */
.stSpinner > div { border-top-color: #fafafa !important; }

/* Alerts */
.stSuccess { background: rgba(34,197,94,0.08) !important; border: 1px solid rgba(34,197,94,0.2) !important; border-radius: 8px !important; }
.stWarning { background: rgba(234,179,8,0.08) !important; border: 1px solid rgba(234,179,8,0.2) !important; border-radius: 8px !important; }
.stError { background: rgba(239,68,68,0.08) !important; border: 1px solid rgba(239,68,68,0.2) !important; border-radius: 8px !important; }
.stInfo { background: rgba(59,130,246,0.08) !important; border: 1px solid rgba(59,130,246,0.2) !important; border-radius: 8px !important; }
</style>
""", unsafe_allow_html=True)

# ── COLORS ───────────────────────────────────────────────
C_BG     = "rgba(0,0,0,0)"
C_PAPER  = "#18181b"
C_GRID   = "rgba(255,255,255,0.04)"
C_TEXT   = "#71717a"
C_GREEN  = "#22c55e"
C_YELLOW = "#eab308"
C_RED    = "#ef4444"
C_BLUE   = "#3b82f6"
C_WHITE  = "#fafafa"

def pc(): return {"displayModeBar": False, "responsive": True}

def sc(s):
    if s >= 80: return C_GREEN
    if s >= 50: return C_YELLOW
    return C_RED

def sl(s):
    if s >= 80: return "Good"
    if s >= 50: return "Needs work"
    return "Critical"

# ── CHARTS ───────────────────────────────────────────────
def gauge(value, label):
    color = sc(value)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=value,
        domain={"x":[0,1],"y":[0,1]},
        title={"text": label, "font":{"size":11,"color":C_TEXT,"family":"Inter"}},
        number={"font":{"size":52,"color":C_WHITE,"family":"Inter"},"suffix":""},
        gauge={
            "axis":{"range":[0,100],"tickcolor":"transparent","tickfont":{"color":"transparent","size":1},"showticklabels":False},
            "bar":{"color":color,"thickness":0.18},
            "bgcolor":"#27272a",
            "borderwidth":0,
            "steps":[{"range":[0,100],"color":"#18181b"}],
        }
    ))
    fig.update_layout(
        paper_bgcolor=C_BG, plot_bgcolor=C_BG,
        margin=dict(l=16,r=16,t=48,b=8), height=180,
        font=dict(family="Inter")
    )
    return fig

def donut(values, labels, colors, title):
    fig = go.Figure(go.Pie(
        values=values, labels=labels, hole=0.72,
        marker=dict(colors=colors, line=dict(color="#09090b",width=3)),
        textinfo="none",
        hovertemplate="%{label}: %{value}<extra></extra>"
    ))
    fig.add_annotation(
        text=f"<b>{values[0]}</b>", x=0.5, y=0.55,
        font=dict(size=24,color=C_WHITE,family="Inter"), showarrow=False
    )
    fig.add_annotation(
        text=labels[0], x=0.5, y=0.38,
        font=dict(size=10,color=C_TEXT,family="Inter"), showarrow=False
    )
    fig.update_layout(
        paper_bgcolor=C_BG, plot_bgcolor=C_BG,
        margin=dict(l=8,r=8,t=40,b=8), height=200,
        title=dict(text=title,font=dict(size=11,color=C_TEXT,family="Inter"),x=0.5),
        showlegend=True,
        legend=dict(font=dict(color=C_TEXT,size=11,family="Inter"),bgcolor="rgba(0,0,0,0)",orientation="h",y=-0.08,x=0.5,xanchor="center"),
        font=dict(family="Inter")
    )
    return fig

def radar(cats, vals, title):
    fig = go.Figure(go.Scatterpolar(
        r=vals+[vals[0]], theta=cats+[cats[0]],
        fill="toself", fillcolor="rgba(250,250,250,0.04)",
        line=dict(color=C_WHITE,width=2),
        marker=dict(color=C_WHITE,size=5),
        hovertemplate="%{theta}: %{r}<extra></extra>"
    ))
    fig.update_layout(
        paper_bgcolor=C_BG, plot_bgcolor=C_BG,
        polar=dict(
            bgcolor="#18181b",
            radialaxis=dict(visible=True,range=[0,100],tickfont=dict(color=C_TEXT,size=9,family="Inter"),gridcolor=C_GRID,linecolor=C_GRID),
            angularaxis=dict(tickfont=dict(color=C_TEXT,size=12,family="Inter"),gridcolor=C_GRID,linecolor=C_GRID)
        ),
        margin=dict(l=40,r=40,t=50,b=40), height=280,
        title=dict(text=title,font=dict(size=11,color=C_TEXT,family="Inter"),x=0.5),
        showlegend=False, font=dict(family="Inter")
    )
    return fig

def line_chart(history):
    if not history: return None
    dates = [s.get("scanned_at","")[:10] for s in reversed(history)]
    scores = [s.get("score_global",0) for s in reversed(history)]
    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=dates, y=scores, mode="lines+markers",
        line=dict(color=C_WHITE,width=2),
        marker=dict(color=C_WHITE,size=6,line=dict(color="#09090b",width=2)),
        fill="tozeroy", fillcolor="rgba(250,250,250,0.03)",
        hovertemplate="%{x}: %{y}/100<extra></extra>"
    ))
    fig.update_layout(
        paper_bgcolor=C_BG, plot_bgcolor=C_BG,
        margin=dict(l=8,r=8,t=8,b=8), height=180,
        xaxis=dict(tickfont=dict(color=C_TEXT,size=10,family="Inter"),gridcolor=C_GRID,showgrid=True,linecolor="transparent"),
        yaxis=dict(tickfont=dict(color=C_TEXT,size=10,family="Inter"),gridcolor=C_GRID,range=[0,105],linecolor="transparent"),
        font=dict(family="Inter")
    )
    return fig

# ── COMPONENTS ───────────────────────────────────────────
def stat(label, value, sub, color=C_WHITE):
    return f"""
    <div style="background:#18181b;border:1px solid #27272a;border-radius:10px;padding:20px 22px;">
      <p style="font-size:11px;font-weight:500;color:#52525b;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:10px;">{label}</p>
      <p style="font-size:30px;font-weight:700;color:{color};line-height:1;letter-spacing:-0.03em;margin-bottom:6px;">{value}</p>
      <p style="font-size:12px;color:#52525b;">{sub}</p>
    </div>"""

def finding(text, level="medium"):
    colors = {"critical":"#ef4444","high":"#f97316","medium":"#eab308","ok":"#22c55e"}
    c = colors.get(level, "#eab308")
    icon = {"critical":"●","high":"●","medium":"●","ok":"✓"}.get(level,"●")
    return f"""
    <div style="display:flex;align-items:flex-start;gap:12px;padding:12px 0;border-bottom:1px solid #18181b;">
      <span style="color:{c};font-size:8px;margin-top:5px;flex-shrink:0;">{icon}</span>
      <span style="font-size:13px;color:#d4d4d8;line-height:1.5;">{text}</span>
    </div>"""

def reco(text):
    return f"""
    <div style="display:flex;align-items:flex-start;gap:12px;padding:12px 0;border-bottom:1px solid #18181b;">
      <span style="color:#3b82f6;font-size:13px;flex-shrink:0;margin-top:1px;">→</span>
      <span style="font-size:13px;color:#a1a1aa;line-height:1.5;">{text}</span>
    </div>"""

def badge(text, color="#27272a", text_color="#a1a1aa"):
    return f'<span style="background:{color};color:{text_color};font-size:11px;font-weight:500;padding:3px 8px;border-radius:4px;letter-spacing:-0.01em;">{text}</span>'

def section_header(title, desc=""):
    desc_html = f'<p style="font-size:13px;color:#52525b;margin-top:4px;">{desc}</p>' if desc else ""
    return f"""
    <div style="margin-bottom:28px;">
      <h2 style="font-size:18px;font-weight:600;letter-spacing:-0.025em;">{title}</h2>
      {desc_html}
    </div>"""

def card_wrap(content, padding="24px"):
    return f'<div style="background:#18181b;border:1px solid #27272a;border-radius:10px;padding:{padding};">{content}</div>'

def policy_row(name, ok):
    color = C_GREEN if ok else C_RED
    icon = "✓" if ok else "✗"
    label = "Active" if ok else "Inactive"
    return f"""
    <div style="display:flex;align-items:center;justify-content:space-between;padding:10px 0;border-bottom:1px solid #18181b;">
      <span style="font-size:13px;color:#d4d4d8;">{name}</span>
      <span style="font-size:12px;font-weight:500;color:{color};">{icon} {label}</span>
    </div>"""

# ── AUTH ─────────────────────────────────────────────────
def sign_in(e, p):
    try: return supabase.auth.sign_in_with_password({"email":e,"password":p}), None
    except Exception as ex: return None, str(ex)

def sign_up(e, p):
    try: return supabase.auth.sign_up({"email":e,"password":p}), None
    except Exception as ex: return None, str(ex)

def sign_out():
    supabase.auth.sign_out()
    st.session_state.clear()
    st.rerun()

# ── LOGIN PAGE ───────────────────────────────────────────
def show_auth():
    _, col, _ = st.columns([1,1,1])
    with col:
        st.markdown("""
        <div style="text-align:center;padding:48px 0 40px;">
          <div style="display:inline-flex;align-items:center;justify-content:center;
               width:44px;height:44px;background:#18181b;border:1px solid #27272a;
               border-radius:10px;margin-bottom:20px;font-size:20px;">🔐</div>
          <h1 style="font-size:26px;font-weight:700;letter-spacing:-0.03em;margin-bottom:8px;">
            CyberSaaS</h1>
          <p style="font-size:14px;color:#52525b;font-weight:400;">
            Audit de securite automatise pour PME</p>
        </div>
        """, unsafe_allow_html=True)

        st.markdown('<div style="background:#18181b;border:1px solid #27272a;border-radius:12px;padding:32px;">', unsafe_allow_html=True)

        if "auth_mode" not in st.session_state:
            st.session_state.auth_mode = "login"

        ca, cb = st.columns(2)
        with ca:
            if st.button("Se connecter", use_container_width=True):
                st.session_state.auth_mode = "login"
        with cb:
            if st.button("Creer un compte", use_container_width=True):
                st.session_state.auth_mode = "signup"

        st.markdown("<div style='height:20px;'></div>", unsafe_allow_html=True)
        email = st.text_input("Email", placeholder="vous@entreprise.fr", key="auth_email")
        password = st.text_input("Mot de passe", type="password", placeholder="8 caracteres minimum", key="auth_pass")
        st.markdown("<div style='height:8px;'></div>", unsafe_allow_html=True)

        label = "Continuer →" if st.session_state.auth_mode == "login" else "Creer mon compte →"
        if st.button(label, use_container_width=True, type="primary"):
            if not email or not password:
                st.warning("Remplis tous les champs.")
            elif st.session_state.auth_mode == "login":
                with st.spinner(""):
                    res, err = sign_in(email, password)
                if err: st.error(err)
                else:
                    st.session_state.user = res.user
                    st.session_state.logged_in = True
                    st.rerun()
            else:
                if len(password) < 8:
                    st.warning("8 caracteres minimum.")
                else:
                    with st.spinner(""): res, err = sign_up(email, password)
                    if err: st.error(err)
                    else:
                        st.success("Compte cree. Verifie ton email.")
                        st.session_state.auth_mode = "login"

        st.markdown("</div>", unsafe_allow_html=True)
        st.markdown('<p style="text-align:center;font-size:12px;color:#3f3f46;margin-top:16px;">Gratuit · Sans CB · RGPD</p>', unsafe_allow_html=True)

# ── MAIN APP ─────────────────────────────────────────────
def show_app():
    user = st.session_state.get("user")

    # Topbar
    c1, c2 = st.columns([5,1])
    with c1:
        st.markdown("""
        <div style="display:flex;align-items:center;gap:12px;padding:4px 0 32px;">
          <div style="display:flex;align-items:center;justify-content:center;
               width:32px;height:32px;background:#18181b;border:1px solid #27272a;
               border-radius:8px;font-size:15px;">🔐</div>
          <span style="font-size:16px;font-weight:600;letter-spacing:-0.02em;">CyberSaaS</span>
          <span style="font-size:11px;font-weight:500;color:#52525b;background:#18181b;
               border:1px solid #27272a;padding:2px 8px;border-radius:4px;">Beta</span>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown(f'<p style="text-align:right;font-size:11px;color:#3f3f46;padding-top:8px;font-family:JetBrains Mono,monospace;">{user.email[:24] if user else ""}</p>', unsafe_allow_html=True)
        if st.button("Exit →"):
            sign_out()

    tab1, tab2, tab3, tab4, tab5 = st.tabs(["Network", "Azure AD", "AI Analysis", "Dashboard", "Report"])

    # ── NETWORK ──────────────────────────────────────────
    with tab1:
        st.markdown(section_header("Network scan", "Ports, SSL certificate and exposed services."), unsafe_allow_html=True)
        c1, c2 = st.columns([5,1])
        with c1:
            target = st.text_input("", placeholder="yourdomain.com or 192.168.1.1", label_visibility="collapsed", key="net_target")
        with c2:
            go = st.button("Scan →", type="primary", use_container_width=True)
        if go and target:
            with st.spinner(f"Scanning {target}..."):
                st.session_state["network_result"] = run_network_scan(target)

        if "network_result" in st.session_state:
            r = st.session_state["network_result"]
            st.markdown("<div style='height:24px;'></div>", unsafe_allow_html=True)
            danger = sum(1 for p in r.open_ports if p.risk=="critical")
            ssl_ok = r.ssl and r.ssl.valid

            c1,c2,c3,c4 = st.columns(4)
            with c1: st.markdown(stat("Score", r.score, f"/100 · {sl(r.score)}", sc(r.score)), unsafe_allow_html=True)
            with c2: st.markdown(stat("Open ports", len(r.open_ports), "detected"), unsafe_allow_html=True)
            with c3: st.markdown(stat("Dangerous", danger, "critical ports", C_RED if danger>0 else C_GREEN), unsafe_allow_html=True)
            with c4: st.markdown(stat("SSL", "Valid" if ssl_ok else "Invalid", r.ssl.message[:28] if r.ssl else "-", C_GREEN if ssl_ok else C_RED), unsafe_allow_html=True)

            st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
            c_l, c_r = st.columns(2)
            with c_l:
                st.markdown('<p style="font-size:13px;font-weight:500;color:#a1a1aa;margin-bottom:4px;">Findings</p>', unsafe_allow_html=True)
                findings_html = "".join(finding(f, "critical" if "🔴" in f else "high" if "🟠" in f else "ok" if "✅" in f else "medium") for f in r.findings)
                st.markdown(card_wrap(findings_html), unsafe_allow_html=True)
            with c_r:
                if r.recommendations:
                    st.markdown('<p style="font-size:13px;font-weight:500;color:#a1a1aa;margin-bottom:4px;">Recommendations</p>', unsafe_allow_html=True)
                    recos_html = "".join(reco(r2) for r2 in r.recommendations)
                    st.markdown(card_wrap(recos_html), unsafe_allow_html=True)

    # ── AZURE AD ─────────────────────────────────────────
    with tab2:
        st.markdown(section_header("Azure AD audit", "MFA coverage, inactive accounts, admin exposure and security policies."), unsafe_allow_html=True)
        c1, c2 = st.columns([5,1])
        with c1:
            company_ad = st.text_input("", placeholder="Company name (e.g. ACME SAS)", label_visibility="collapsed", key="ad_company")
        with c2:
            scan_ad = st.button("Scan →", type="primary", use_container_width=True, key="btn_ad")
        st.markdown('<p style="font-size:12px;color:#3f3f46;margin-top:8px;">Demo mode · Simulated realistic data · Real OAuth connection available in Pro</p>', unsafe_allow_html=True)

        if scan_ad and company_ad:
            with st.spinner("Connecting to Azure AD..."):
                time.sleep(1.5)
                tenant = generate_fake_tenant(company_ad)
                result = analyze_azure_ad(tenant)
                st.session_state["ad_result"] = result
                st.session_state["ad_tenant"] = tenant

        if "ad_result" in st.session_state:
            r = st.session_state["ad_result"]
            st.markdown("<div style='height:24px;'></div>", unsafe_allow_html=True)

            c1,c2,c3,c4 = st.columns(4)
            with c1: st.markdown(stat("Access score", r.score, f"/100 · {sl(r.score)}", sc(r.score)), unsafe_allow_html=True)
            with c2: st.markdown(stat("MFA coverage", f"{r.mfa_enabled_pct}%", "of all users", sc(r.mfa_enabled_pct)), unsafe_allow_html=True)
            with c3: st.markdown(stat("Inactive", r.inactive_count, "accounts > 90 days", C_RED if r.inactive_count>3 else C_YELLOW), unsafe_allow_html=True)
            with c4: st.markdown(stat("Admins", r.admin_count, "privileged accounts", C_YELLOW if r.admin_count>3 else C_GREEN), unsafe_allow_html=True)

            st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)

            c1, c2, c3 = st.columns(3)
            with c1:
                mfa_on = int(r.mfa_enabled_pct * r.total_users / 100)
                st.plotly_chart(donut([mfa_on, r.total_users-mfa_on], ["MFA on","No MFA"], [C_GREEN,C_RED], "MFA STATUS"), use_container_width=True, config=pc())
            with c2:
                st.plotly_chart(donut([r.total_users-r.inactive_count, r.inactive_count], ["Active","Inactive"], [C_BLUE,C_YELLOW], "ACCOUNT STATUS"), use_container_width=True, config=pc())
            with c3:
                st.plotly_chart(donut([r.device_results.get("compliant_pct",0), 100-r.device_results.get("compliant_pct",0)], ["Compliant","Non-compliant"], [C_GREEN,C_RED], "DEVICE COMPLIANCE"), use_container_width=True, config=pc())

            st.markdown("<div style='height:28px;'></div>", unsafe_allow_html=True)
            c_l, c_r = st.columns(2)
            with c_l:
                st.markdown('<p style="font-size:13px;font-weight:500;color:#a1a1aa;margin-bottom:4px;">Security policies</p>', unsafe_allow_html=True)
                policies_html = "".join(policy_row(k,v) for k,v in r.policy_results.items())
                st.markdown(card_wrap(policies_html), unsafe_allow_html=True)
            with c_r:
                st.markdown('<p style="font-size:13px;font-weight:500;color:#a1a1aa;margin-bottom:4px;">Findings</p>', unsafe_allow_html=True)
                findings_html = "".join(finding(f, "critical" if "🔴" in f else "high" if "🟠" in f else "ok" if "✅" in f else "medium") for f in r.findings[:6])
                st.markdown(card_wrap(findings_html), unsafe_allow_html=True)

            if r.recommendations:
                st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
                st.markdown('<p style="font-size:13px;font-weight:500;color:#a1a1aa;margin-bottom:4px;">Recommendations</p>', unsafe_allow_html=True)
                c1, c2 = st.columns(2)
                recos = r.recommendations[:6]
                half = len(recos)//2
                with c1: st.markdown(card_wrap("".join(reco(r2) for r2 in recos[:half+1])), unsafe_allow_html=True)
                with c2: st.markdown(card_wrap("".join(reco(r2) for r2 in recos[half+1:])), unsafe_allow_html=True)

            if r.risky_users:
                st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
                st.markdown('<p style="font-size:13px;font-weight:500;color:#a1a1aa;margin-bottom:4px;">At-risk users</p>', unsafe_allow_html=True)
                for u in r.risky_users[:4]:
                    st.markdown(f"""
                    <div style="display:flex;align-items:center;gap:16px;padding:12px 16px;
                         background:#18181b;border:1px solid #27272a;border-radius:8px;margin-bottom:4px;">
                      <div style="width:32px;height:32px;background:#27272a;border-radius:50%;
                           display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:600;
                           flex-shrink:0;">{u.name[0] if u.name else "?"}</div>
                      <div style="flex:1;">
                        <p style="font-size:13px;font-weight:500;margin-bottom:2px;">{u.name}</p>
                        <p style="font-size:11px;color:#52525b;font-family:JetBrains Mono,monospace;">{u.email}</p>
                      </div>
                      <span style="font-size:11px;font-weight:500;color:{C_RED};background:rgba(239,68,68,0.1);
                            padding:3px 8px;border-radius:4px;">{', '.join(u.risks)}</span>
                    </div>""", unsafe_allow_html=True)

    # ── AI ANALYSIS ──────────────────────────────────────
    with tab3:
        st.markdown(section_header("AI file analysis", "Upload logs, firewall configs, AD exports — our AI detects vulnerabilities automatically."), unsafe_allow_html=True)
        c1, c2 = st.columns([2,1])
        with c1:
            api_key = st.text_input("Anthropic API key", type="password", placeholder="sk-ant-...", key="api_key")
        with c2:
            st.markdown('<p style="font-size:12px;color:#3f3f46;margin-top:36px;">Get your key at <a href="https://console.anthropic.com" target="_blank" style="color:#3b82f6;">console.anthropic.com</a></p>', unsafe_allow_html=True)
        uploaded = st.file_uploader("", type=["txt","log","csv","json","conf","cfg","xml","ini"], label_visibility="collapsed")
        if uploaded and api_key:
            if st.button("Analyze with AI →", type="primary"):
                content = uploaded.read().decode("utf-8", errors="ignore")
                with st.spinner(f"Analyzing {uploaded.name}..."):
                    result = analyze_file_sync(content, uploaded.name, api_key)
                    st.session_state["ai_result"] = result

        if "ai_result" in st.session_state:
            r = st.session_state["ai_result"]
            st.markdown("<div style='height:24px;'></div>", unsafe_allow_html=True)
            c1,c2,c3 = st.columns(3)
            with c1: st.markdown(stat("AI Score", r.score, f"/100 · {sl(r.score)}", sc(r.score)), unsafe_allow_html=True)
            with c2: st.markdown(stat("File type", r.file_type[:20], "detected"), unsafe_allow_html=True)
            with c3: st.markdown(stat("Gaps found", len(r.compliance_gaps), "compliance issues", C_RED if len(r.compliance_gaps)>2 else C_YELLOW), unsafe_allow_html=True)
            st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
            st.markdown(card_wrap(f'<p style="font-size:13px;color:#a1a1aa;line-height:1.6;">{r.summary}</p>'), unsafe_allow_html=True)
            st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
            c_l, c_r = st.columns(2)
            with c_l:
                st.markdown('<p style="font-size:13px;font-weight:500;color:#a1a1aa;margin-bottom:4px;">Vulnerabilities</p>', unsafe_allow_html=True)
                st.markdown(card_wrap("".join(finding(f,"critical") for f in r.findings)), unsafe_allow_html=True)
            with c_r:
                st.markdown('<p style="font-size:13px;font-weight:500;color:#a1a1aa;margin-bottom:4px;">Recommendations</p>', unsafe_allow_html=True)
                st.markdown(card_wrap("".join(reco(r2) for r2 in r.recommendations)), unsafe_allow_html=True)

    # ── DASHBOARD ────────────────────────────────────────
    with tab4:
        has_n = "network_result" in st.session_state
        has_a = "ad_result" in st.session_state
        has_ai = "ai_result" in st.session_state
        scores = []
        if has_n: scores.append(st.session_state["network_result"].score)
        if has_a: scores.append(st.session_state["ad_result"].score)
        if has_ai: scores.append(st.session_state["ai_result"].score)

        if scores:
            g = sum(scores)//len(scores)
            st.markdown(f"""
            <div style="background:#18181b;border:1px solid #27272a;border-radius:12px;
                 padding:32px 40px;margin-bottom:28px;display:flex;align-items:center;gap:32px;">
              <div>
                <p style="font-size:11px;font-weight:500;color:#52525b;text-transform:uppercase;
                     letter-spacing:0.06em;margin-bottom:8px;">Global security score</p>
                <p style="font-size:64px;font-weight:700;color:{sc(g)};line-height:1;
                     letter-spacing:-0.04em;">{g}<span style="font-size:24px;color:#52525b;font-weight:400;">/100</span></p>
                <p style="font-size:14px;color:#71717a;margin-top:8px;">{sl(g)}</p>
              </div>
              <div style="flex:1;border-left:1px solid #27272a;padding-left:32px;">
                <div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:16px;">
                  {"".join(f'<div><p style="font-size:11px;color:#52525b;margin-bottom:4px;">{n}</p><p style="font-size:22px;font-weight:600;color:{sc(v)};letter-spacing:-0.02em;">{v}</p></div>' for n,v in [("Network", st.session_state["network_result"].score if has_n else "—"),("Azure AD", st.session_state["ad_result"].score if has_a else "—"),("AI Analysis", st.session_state["ai_result"].score if has_ai else "—")])}
                </div>
              </div>
            </div>""", unsafe_allow_html=True)

            cats, vals = [], []
            if has_n: cats.append("Network"); vals.append(st.session_state["network_result"].score)
            if has_a: cats.append("Azure AD"); vals.append(st.session_state["ad_result"].score)
            if has_ai: cats.append("AI"); vals.append(st.session_state["ai_result"].score)
            if len(cats) >= 3:
                st.plotly_chart(radar(cats, vals, "SECURITY PROFILE"), use_container_width=True, config=pc())

            st.markdown("<div style='height:16px;'></div>", unsafe_allow_html=True)
            c1, c2 = st.columns([4,1])
            with c1:
                company_save = st.text_input("", placeholder="Company name to save this scan", label_visibility="collapsed", key="save_company")
            with c2:
                if st.button("Save scan →", type="primary", use_container_width=True):
                    if company_save:
                        sc_data = {"global":g, "network": st.session_state["network_result"].score if has_n else 0, "access": st.session_state["ad_result"].score if has_a else 0, "compliance": st.session_state["ai_result"].score if has_ai else 0}
                        findings_data = {"network": st.session_state["network_result"].findings if has_n else [], "access": st.session_state["ad_result"].findings if has_a else []}
                        ok = save_scan(supabase, user.id, company_save, sc_data, findings_data)
                        if ok: st.success("Scan saved.")
                        else: st.info("Create the 'scans' table in Supabase to enable history.")
        else:
            st.markdown("""
            <div style="text-align:center;padding:80px;background:#18181b;border:1px solid #27272a;border-radius:12px;">
              <p style="font-size:40px;margin-bottom:16px;">📊</p>
              <p style="font-size:16px;font-weight:600;margin-bottom:8px;">No data yet</p>
              <p style="font-size:13px;color:#52525b;">Run the Network and Azure AD scans to populate your dashboard.</p>
            </div>""", unsafe_allow_html=True)

        history = get_scan_history(supabase, user.id if user else "")
        if history:
            st.markdown("<div style='height:24px;'></div>", unsafe_allow_html=True)
            st.markdown('<p style="font-size:13px;font-weight:500;color:#a1a1aa;margin-bottom:12px;">Scan history</p>', unsafe_allow_html=True)
            ch = line_chart(history)
            if ch: st.plotly_chart(ch, use_container_width=True, config=pc())
            for scan in history[:5]:
                sg = scan.get("score_global",0)
                st.markdown(f"""
                <div style="display:flex;align-items:center;gap:20px;padding:12px 0;border-bottom:1px solid #18181b;">
                  <span style="font-size:18px;font-weight:700;color:{sc(sg)};min-width:36px;letter-spacing:-0.02em;">{sg}</span>
                  <span style="font-size:13px;font-weight:500;flex:1;">{scan.get('company_name','')}</span>
                  <span style="font-size:11px;color:#52525b;font-family:JetBrains Mono,monospace;">{scan.get('scanned_at','')[:10]}</span>
                </div>""", unsafe_allow_html=True)

    # ── REPORT ───────────────────────────────────────────
    with tab5:
        st.markdown(section_header("Generate report", "Professional PDF report ready for clients and auditors."), unsafe_allow_html=True)
        has_n = "network_result" in st.session_state
        has_acc = "access_result" in st.session_state
        has_c = "compliance_result" in st.session_state

        c1, c2 = st.columns([4,1])
        with c1:
            company_r = st.text_input("", placeholder="Company name", label_visibility="collapsed", key="report_company")
        with c2:
            if st.button("Generate →", type="primary", use_container_width=True, disabled=not company_r):
                if not all([has_n, has_acc, has_c]):
                    st.warning("Complete the Network, Access and Compliance modules first.")
                else:
                    with st.spinner("Generating..."):
                        html = generate_html_report(company_name=company_r, network=st.session_state["network_result"], access=st.session_state["access_result"], compliance=st.session_state["compliance_result"])
                    st.download_button("Download report", data=html, file_name=f"report_{company_r.lower().replace(' ','_')}.html", mime="text/html")
                    st.success("Open in browser and print as PDF.")

        st.markdown(f"""
        <div style="display:flex;gap:8px;margin-top:20px;">
          {"".join(f'<div style="background:#18181b;border:1px solid {"#27272a" if not v else "#22c55e22"};border-radius:6px;padding:8px 16px;font-size:12px;color:{"#52525b" if not v else "#22c55e"};">{"✓" if v else "○"} {n}</div>' for n,v in [("Network",has_n),("Access",has_acc),("Compliance",has_c)])}
        </div>""", unsafe_allow_html=True)

# ── ROUTING ──────────────────────────────────────────────
if not st.session_state.get("logged_in"):
    show_auth()
else:
    show_app()
