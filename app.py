"""
Enterprise GRC & Compliance Automation Dashboard
================================================
Author  : Senior Python Developer / Cyber GRC Architect
Purpose : Bridge technical vulnerabilities to ISO 27001:2022 and SOC 2 controls,
          producing interactive executive dashboards and downloadable PDF reports.
Run     : streamlit run app.py
"""

import io
import math
import random
import datetime
from typing import Optional

import numpy as np
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
import streamlit as st
from fpdf import FPDF

# ──────────────────────────────────────────────
# PAGE CONFIGURATION
# ──────────────────────────────────────────────
st.set_page_config(
    page_title="Enterprise GRC Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────
# GLOBAL THEME & CSS
# ──────────────────────────────────────────────
DARK_BG       = "#0D1117"
CARD_BG       = "#161B22"
BORDER        = "#30363D"
ACCENT_BLUE   = "#58A6FF"
ACCENT_GREEN  = "#3FB950"
ACCENT_ORANGE = "#F0883E"
ACCENT_RED    = "#F85149"
TEXT_PRIMARY  = "#E6EDF3"
TEXT_MUTED    = "#8B949E"

SEVERITY_COLOR = {
    "Critical": ACCENT_RED,
    "High":     ACCENT_ORANGE,
    "Medium":   "#D29922",
    "Low":      ACCENT_GREEN,
}

SEVERITY_WEIGHT = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
FINANCIAL_WEIGHT = {"Critical": 150_000, "High": 75_000, "Medium": 25_000, "Low": 5_000}

st.markdown(f"""
<style>
/* ── Root ── */
html, body, [class*="css"] {{
    background-color: {DARK_BG};
    color: {TEXT_PRIMARY};
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
}}
[data-testid="stAppViewContainer"] {{
    background-color: {DARK_BG};
}}
[data-testid="stSidebar"] {{
    background-color: {CARD_BG};
    border-right: 1px solid {BORDER};
}}
/* ── Metric cards ── */
.metric-card {{
    background: {CARD_BG};
    border: 1px solid {BORDER};
    border-radius: 12px;
    padding: 20px 24px;
    text-align: left;
    position: relative;
    overflow: hidden;
}}
.metric-card::before {{
    content: "";
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 3px;
}}
.metric-card.blue::before  {{ background: {ACCENT_BLUE}; }}
.metric-card.red::before   {{ background: {ACCENT_RED}; }}
.metric-card.green::before {{ background: {ACCENT_GREEN}; }}
.metric-card.orange::before {{ background: {ACCENT_ORANGE}; }}
.metric-label {{
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.08em;
    text-transform: uppercase;
    color: {TEXT_MUTED};
    margin-bottom: 8px;
}}
.metric-value {{
    font-size: 32px;
    font-weight: 700;
    color: {TEXT_PRIMARY};
    line-height: 1;
    margin-bottom: 6px;
}}
.metric-sub {{
    font-size: 12px;
    color: {TEXT_MUTED};
}}
/* ── Section headers ── */
.section-header {{
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 16px 0 12px;
    border-bottom: 1px solid {BORDER};
    margin-bottom: 20px;
}}
.section-title {{
    font-size: 16px;
    font-weight: 600;
    color: {TEXT_PRIMARY};
    letter-spacing: 0.02em;
}}
.section-badge {{
    font-size: 11px;
    font-weight: 600;
    color: {ACCENT_BLUE};
    background: rgba(88,166,255,0.12);
    border: 1px solid rgba(88,166,255,0.25);
    border-radius: 20px;
    padding: 2px 10px;
}}
/* ── Table ── */
.grc-table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 13px;
}}
.grc-table th {{
    background: #1C2128;
    color: {TEXT_MUTED};
    font-weight: 600;
    letter-spacing: 0.06em;
    text-transform: uppercase;
    font-size: 11px;
    padding: 10px 14px;
    text-align: left;
    border-bottom: 1px solid {BORDER};
}}
.grc-table td {{
    padding: 10px 14px;
    border-bottom: 1px solid {BORDER};
    color: {TEXT_PRIMARY};
    vertical-align: middle;
}}
.grc-table tr:hover td {{ background: rgba(88,166,255,0.04); }}
.sev-badge {{
    display: inline-block;
    padding: 2px 10px;
    border-radius: 20px;
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.04em;
}}
.sev-Critical {{ background:rgba(248,81,73,0.18);  color:{ACCENT_RED};    border:1px solid rgba(248,81,73,0.3); }}
.sev-High     {{ background:rgba(240,136,62,0.18); color:{ACCENT_ORANGE}; border:1px solid rgba(240,136,62,0.3); }}
.sev-Medium   {{ background:rgba(210,153,34,0.18); color:#D29922;         border:1px solid rgba(210,153,34,0.3); }}
.sev-Low      {{ background:rgba(63,185,80,0.18);  color:{ACCENT_GREEN};  border:1px solid rgba(63,185,80,0.3); }}
/* ── Compliance bar ── */
.compliance-bar-wrap {{
    background: #1C2128;
    border-radius: 6px;
    height: 8px;
    overflow: hidden;
    margin-top: 6px;
}}
.compliance-bar-fill {{
    height: 100%;
    border-radius: 6px;
    transition: width 0.5s ease;
}}
/* ── Plotly background fix ── */
.js-plotly-plot .plotly .modebar {{ background: transparent !important; }}
/* ── Buttons ── */
.stButton > button {{
    background: linear-gradient(135deg, {ACCENT_BLUE}, #1F6FEB);
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    padding: 10px 24px;
    font-size: 14px;
    cursor: pointer;
    transition: opacity 0.2s;
}}
.stButton > button:hover {{ opacity: 0.88; }}
/* ── Download button ── */
.stDownloadButton > button {{
    background: linear-gradient(135deg, {ACCENT_GREEN}, #2DA44E);
    color: white;
    border: none;
    border-radius: 8px;
    font-weight: 600;
    padding: 10px 24px;
    font-size: 14px;
}}
/* Hide Streamlit chrome ── */
#MainMenu, footer, [data-testid="stDecoration"] {{ visibility: hidden; }}
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────
# MOCK DATA GENERATOR
# ──────────────────────────────────────────────
MOCK_VULNERABILITIES = [
    ("Default Credentials Exposed",       "Critical"),
    ("Brute Force Attack Surface",         "High"),
    ("SSL 2.0 Deprecated Protocol",        "Critical"),
    ("TLS 1.0 Enabled",                    "High"),
    ("Unencrypted HTTP Traffic",           "High"),
    ("Outdated OpenSSL (RCE vector)",      "Critical"),
    ("Missing OS Patch - MS17-010",        "Critical"),
    ("Old Version Apache 2.2",             "Medium"),
    ("Open Port 23 (Telnet)",              "High"),
    ("SSH Root Login Permitted",           "High"),
    ("Cleartext FTP Credentials",          "Medium"),
    ("Authentication Bypass Possible",     "Critical"),
    ("RCE via PHP Deserialization",        "Critical"),
    ("Open Port 3389 - No MFA",            "High"),
    ("Weak TLS Cipher Suites",             "Medium"),
    ("Outdated jQuery Library",            "Low"),
    ("Patch Missing - Log4Shell",          "Critical"),
    ("SSH v1 Protocol Active",             "Medium"),
    ("Brute Force on Admin Panel",         "High"),
    ("Unencrypted Database Connection",    "Critical"),
    ("Old Version PHP 5.6",               "High"),
    ("Open Port 21 (FTP Anonymous)",       "Medium"),
    ("SSL Certificate Expired",            "High"),
    ("Missing Authentication on API",      "Critical"),
    ("Credentials in Environment Variables","Medium"),
    ("Telnet Service Active",              "High"),
    ("Outdated Nginx 1.12",               "Low"),
    ("Cleartext SMTP Auth",               "Medium"),
    ("RCE via Shell Injection",            "Critical"),
    ("TLS Certificate Mismatch",           "Low"),
]

ASSET_NAMES = [
    "web-prod-01", "db-server-02", "api-gateway-03", "auth-service-04",
    "mail-server-05", "vpn-endpoint-06", "hr-portal-07", "ci-cd-pipeline-08",
    "backup-server-09", "firewall-cluster-10",
]

ASSET_CATEGORIES = {
    "web-prod-01":       "Web Application",
    "db-server-02":      "Database",
    "api-gateway-03":    "API / Middleware",
    "auth-service-04":   "Identity & Access",
    "mail-server-05":    "Email Infrastructure",
    "vpn-endpoint-06":   "Network Security",
    "hr-portal-07":      "Web Application",
    "ci-cd-pipeline-08": "DevOps / CI-CD",
    "backup-server-09":  "Data Storage",
    "firewall-cluster-10":"Network Security",
}


def generate_mock_data(n: int = 30) -> pd.DataFrame:
    random.seed(42)
    rows = []
    for i in range(n):
        asset = random.choice(ASSET_NAMES)
        vuln, severity = MOCK_VULNERABILITIES[i % len(MOCK_VULNERABILITIES)]
        rows.append({
            "Asset_ID":    f"ASSET-{100 + i}",
            "Asset_Name":  asset,
            "Vulnerability": vuln,
            "Severity":    severity,
            "IP_Address":  f"10.{random.randint(0,3)}.{random.randint(1,254)}.{random.randint(1,254)}",
            "Port":        random.choice([22, 80, 443, 21, 23, 3306, 5432, 3389, 8080, 8443]),
        })
    return pd.DataFrame(rows)


# ──────────────────────────────────────────────
# GRC MAPPING ENGINE
# ──────────────────────────────────────────────
CONTROL_DESCRIPTIONS = {
    "SOC 2 CC6.1 / ISO 27001 A.8.20 - Access Control":
        "Logical and physical access controls, authentication policy, and user provisioning.",
    "ISO 27001 A.8.24 / SOC 2 CC6.3 - Cryptography":
        "Encryption in transit and at rest, certificate lifecycle, cipher suite management.",
    "ISO 27001 A.8.19 - Technical Vulnerability Management":
        "Patch management, software lifecycle, version control, and exploit mitigation.",
    "ISO 27001 A.8.20 - Network Security":
        "Network segmentation, firewall rules, open port policy, and insecure protocol removal.",
    "NIST SP 800-53 - General Risk Treatment":
        "Residual risk accepted under documented risk treatment plan; periodic review required.",
}

LIKELIHOOD_MAP = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2}
IMPACT_MAP     = {"Critical": 5, "High": 4, "Medium": 3, "Low": 1}
RESIDUAL_REDUCTION = 0.40   # assumed 40% risk reduction after controls applied


def map_to_control(vulnerability: str) -> str:
    v = vulnerability.upper()
    if any(k in v for k in ["CREDENTIAL", "BRUTE FORCE", "AUTHENTICATION", "AUTH"]):
        return "SOC 2 CC6.1 / ISO 27001 A.8.20 - Access Control"
    if any(k in v for k in ["SSL", "TLS", "UNENCRYPT", "CLEARTEXT", "CIPHER"]):
        return "ISO 27001 A.8.24 / SOC 2 CC6.3 - Cryptography"
    if any(k in v for k in ["PATCH", "OUTDATED", "OLD VERSION", "RCE", "LOG4", "DESERIALIZ"]):
        return "ISO 27001 A.8.19 - Technical Vulnerability Management"
    if any(k in v for k in ["OPEN PORT", "SSH", "TELNET", "FTP", "PORT"]):
        return "ISO 27001 A.8.20 - Network Security"
    return "NIST SP 800-53 - General Risk Treatment"


def enrich_dataframe(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df["Asset_Category"] = df["Asset_Name"].map(ASSET_CATEGORIES).fillna("General IT")
    df["Control_Mapping"] = df["Vulnerability"].apply(map_to_control)
    df["Likelihood"]      = df["Severity"].map(LIKELIHOOD_MAP).fillna(3)
    df["Impact"]          = df["Severity"].map(IMPACT_MAP).fillna(2)
    df["Inherent_Risk"]   = df["Likelihood"] * df["Impact"]
    df["Residual_Risk"]   = (df["Inherent_Risk"] * (1 - RESIDUAL_REDUCTION)).round(1)
    df["Financial_Exposure"] = df["Severity"].map(FINANCIAL_WEIGHT).fillna(5_000)
    return df


# ──────────────────────────────────────────────
# COMPLIANCE SCORE CALCULATOR
# ──────────────────────────────────────────────
def compliance_score(df: pd.DataFrame) -> float:
    """
    Score = 100 - weighted_penalty.
    Each open finding penalises the score weighted by severity.
    Designed so a 30-finding mixed-severity scan → ~45-65% range.
    """
    weights       = df["Severity"].map(SEVERITY_WEIGHT).fillna(1)
    total_penalty = weights.sum()
    # Max possible penalty for 30 findings all Critical = 30*4 = 120
    # We want that to map to ~0%; 0 findings = 100%
    # Use a per-finding average cap so one Critical doesn't nuke the score
    max_penalty = len(df) * SEVERITY_WEIGHT["Critical"]   # worst-case ceiling
    if max_penalty == 0:
        return 99.0
    score = max(0.0, 100.0 * (1.0 - total_penalty / max_penalty))
    # Boost slightly so a well-managed org (mostly Medium/Low) scores above 50
    score = min(score * 1.3, 99.0)
    return round(score, 1)


def score_color(score: float) -> str:
    if score >= 75:
        return ACCENT_GREEN
    if score >= 50:
        return "#D29922"
    return ACCENT_RED


# ──────────────────────────────────────────────
# PLOTLY CHART HELPERS  (dark-theme wrappers)
# ──────────────────────────────────────────────
PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color=TEXT_PRIMARY, family="Segoe UI, system-ui, sans-serif"),
    margin=dict(l=10, r=10, t=40, b=10),
)


def build_heat_matrix(df: pd.DataFrame) -> go.Figure:
    """5×5 Risk Heat Matrix coloured by risk level."""
    grid = np.zeros((5, 5), dtype=int)
    for _, row in df.iterrows():
        l = int(np.clip(row["Likelihood"], 1, 5)) - 1
        i = int(np.clip(row["Impact"], 1, 5)) - 1
        grid[l][i] += 1

    # Build colour surface: product l*i
    color_grid = np.array([[((r + 1) * (c + 1)) for c in range(5)] for r in range(5)],
                           dtype=float)

    labels_axis = ["1 – Rare", "2 – Unlikely", "3 – Possible", "4 – Likely", "5 – Almost Certain"]
    impact_axis = ["1 – Negligible", "2 – Minor", "3 – Moderate", "4 – Major", "5 – Catastrophic"]

    # Text in each cell: count of findings
    text_grid = [[str(grid[r][c]) if grid[r][c] > 0 else "" for c in range(5)] for r in range(5)]

    fig = go.Figure(go.Heatmap(
        z=color_grid,
        text=text_grid,
        texttemplate="%{text}",
        textfont=dict(size=14, color="white"),
        x=impact_axis,
        y=labels_axis,
        colorscale=[
            [0.00, "#1F3A1F"],
            [0.20, "#2DA44E"],
            [0.40, "#D29922"],
            [0.65, "#F0883E"],
            [1.00, "#F85149"],
        ],
        showscale=False,
        hoverongaps=False,
        hovertemplate="Likelihood: %{y}<br>Impact: %{x}<br>Findings: %{text}<extra></extra>",
    ))
    fig.update_layout(
        **PLOTLY_LAYOUT,
        title=dict(text="Risk Heat Matrix - Likelihood vs Impact", font=dict(size=14)),
        xaxis=dict(title="Impact →", tickfont=dict(size=11), gridcolor=BORDER),
        yaxis=dict(title="Likelihood →", tickfont=dict(size=11), gridcolor=BORDER),
        height=380,
    )
    return fig


def build_control_gap_chart(df: pd.DataFrame) -> go.Figure:
    """Horizontal bar chart: number of findings per control category."""
    control_counts = (
        df.groupby(["Control_Mapping", "Severity"])
          .size()
          .reset_index(name="Count")
    )
    # Short labels for readability
    control_counts["Short_Label"] = control_counts["Control_Mapping"].str.split("-").str[0].str.strip()

    fig = px.bar(
        control_counts,
        x="Count",
        y="Short_Label",
        color="Severity",
        orientation="h",
        color_discrete_map=SEVERITY_COLOR,
        category_orders={"Severity": ["Critical", "High", "Medium", "Low"]},
    )
    fig.update_layout(
        **PLOTLY_LAYOUT,
        title=dict(text="Compliance Gaps — Findings per Control Domain", font=dict(size=14)),
        xaxis=dict(title="Number of Findings", gridcolor=BORDER),
        yaxis=dict(title="", gridcolor=BORDER),
        legend=dict(orientation="h", y=-0.15, font=dict(size=11)),
        height=360,
        barmode="stack",
    )
    return fig


def build_severity_donut(df: pd.DataFrame) -> go.Figure:
    counts = df["Severity"].value_counts().reindex(["Critical", "High", "Medium", "Low"], fill_value=0)
    fig = go.Figure(go.Pie(
        labels=counts.index,
        values=counts.values,
        hole=0.62,
        marker=dict(colors=[SEVERITY_COLOR[s] for s in counts.index]),
        textinfo="label+percent",
        textfont=dict(size=12),
        hovertemplate="%{label}: %{value} findings<extra></extra>",
    ))
    fig.add_annotation(
        text=f"<b>{counts.sum()}</b><br><span style='font-size:11px'>Total</span>",
        x=0.5, y=0.5, showarrow=False,
        font=dict(size=18, color=TEXT_PRIMARY),
    )
    fig.update_layout(
        **PLOTLY_LAYOUT,
        title=dict(text="Severity Distribution", font=dict(size=14)),
        showlegend=False,
        height=300,
    )
    return fig


def build_inherent_vs_residual(df: pd.DataFrame) -> go.Figure:
    grouped = (
        df.groupby("Asset_Name")
          .agg(Inherent_Risk=("Inherent_Risk", "sum"),
               Residual_Risk=("Residual_Risk", "sum"))
          .sort_values("Inherent_Risk", ascending=True)
          .tail(8)
          .reset_index()
    )
    fig = go.Figure()
    fig.add_trace(go.Bar(
        name="Inherent Risk",
        y=grouped["Asset_Name"],
        x=grouped["Inherent_Risk"],
        orientation="h",
        marker_color=ACCENT_RED,
        opacity=0.85,
    ))
    fig.add_trace(go.Bar(
        name="Residual Risk (post-control)",
        y=grouped["Asset_Name"],
        x=grouped["Residual_Risk"],
        orientation="h",
        marker_color=ACCENT_BLUE,
        opacity=0.85,
    ))
    fig.update_layout(
        **PLOTLY_LAYOUT,
        title=dict(text="Inherent vs Residual Risk by Asset (Top 8)", font=dict(size=14)),
        xaxis=dict(title="Risk Score", gridcolor=BORDER),
        yaxis=dict(gridcolor=BORDER),
        barmode="overlay",
        legend=dict(orientation="h", y=-0.18, font=dict(size=11)),
        height=340,
    )
    return fig


# ──────────────────────────────────────────────
# PDF REPORT GENERATOR
# ──────────────────────────────────────────────
class GRCReport(FPDF):
    def __init__(self, org_name: str, score: float):
        super().__init__()
        self.org_name  = org_name
        self.score     = score
        self.generated = datetime.datetime.utcnow().strftime("%d %B %Y, %H:%M UTC")

    @staticmethod
    def safe(text: str) -> str:
        """Strip or replace characters outside latin-1 so Helvetica never crashes."""
        return (text
                .replace("\u2014", "-")   # em-dash
                .replace("\u2013", "-")   # en-dash
                .replace("\u2026", "...") # ellipsis
                .replace("\u2018", "'")   # left single quote
                .replace("\u2019", "'")   # right single quote
                .replace("\u201c", '"')   # left double quote
                .replace("\u201d", '"')   # right double quote
                .encode("latin-1", errors="replace").decode("latin-1")
                )

    # ─── Header (every page) ───
    def header(self):
        # Navy banner
        self.set_fill_color(13, 17, 23)
        self.rect(0, 0, 210, 22, "F")
        self.set_font("Helvetica", "B", 12)
        self.set_text_color(88, 166, 255)
        self.set_xy(10, 6)
        self.cell(0, 10, self.safe("ENTERPRISE GRC & COMPLIANCE AUTOMATION DASHBOARD"), ln=0)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(139, 148, 158)
        self.set_xy(10, 14)
        self.cell(0, 5, self.safe(f"CONFIDENTIAL - {self.generated}"), ln=0)
        self.ln(16)

    # ─── Footer (every page) ───
    def footer(self):
        self.set_y(-14)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(139, 148, 158)
        self.cell(0, 10, self.safe(f"Page {self.page_no()} | {self.org_name} - GRC Compliance Report"), align="C")

    # ─── Section title ───
    def section_title(self, title: str):
        self.ln(4)
        self.set_font("Helvetica", "B", 11)
        self.set_text_color(88, 166, 255)
        self.set_fill_color(22, 27, 34)
        self.cell(0, 9, self.safe(f"  {title}"), border=0, ln=1, fill=True)
        # thin underline
        self.set_draw_color(48, 54, 61)
        self.set_line_width(0.4)
        x = self.get_x()
        y = self.get_y()
        self.line(10, y, 200, y)
        self.ln(3)
        self.set_text_color(230, 237, 243)

    # ─── Score gauge (text-based) ───
    def score_gauge(self, score: float):
        bar_width = 150
        filled    = int(bar_width * score / 100)

        self.set_font("Helvetica", "B", 28)
        if score >= 75:
            self.set_text_color(63, 185, 80)
        elif score >= 50:
            self.set_text_color(210, 153, 34)
        else:
            self.set_text_color(248, 81, 73)
        self.cell(0, 14, self.safe(f"{score}%"), ln=1)

        self.set_text_color(230, 237, 243)
        self.set_font("Helvetica", "", 9)
        grade = "ADEQUATE" if score >= 75 else ("NEEDS IMPROVEMENT" if score >= 50 else "AT RISK")
        self.cell(0, 5, self.safe(f"Overall Compliance Posture: {grade}"), ln=1)
        self.ln(2)

        # Bar (drawn with coloured rect)
        bx, by = self.get_x(), self.get_y()
        self.set_fill_color(28, 33, 40)
        self.rect(bx, by, bar_width, 5, "F")
        if score >= 75:
            self.set_fill_color(63, 185, 80)
        elif score >= 50:
            self.set_fill_color(210, 153, 34)
        else:
            self.set_fill_color(248, 81, 73)
        self.rect(bx, by, filled, 5, "F")
        self.ln(10)


def generate_pdf_report(df: pd.DataFrame, score: float, org_name: str = "Acme Corporation") -> bytes:
    """
    Generates a complete executive GRC PDF report.
    Returns the PDF as bytes for Streamlit download.
    """
    criticals = df[df["Severity"] == "Critical"]
    highs     = df[df["Severity"] == "High"]
    total_exposure = int(df["Financial_Exposure"].sum())
    top_controls   = df["Control_Mapping"].value_counts().head(5)

    pdf = GRCReport(org_name, score)
    pdf.set_auto_page_break(auto=True, margin=18)
    pdf.add_page()

    # ── Title block ─────────────────────────────
    pdf.set_fill_color(22, 27, 34)
    pdf.set_draw_color(48, 54, 61)
    pdf.set_line_width(0.5)
    pdf.rect(10, 26, 190, 38, "DF")

    pdf.set_xy(14, 30)
    pdf.set_font("Helvetica", "B", 18)
    pdf.set_text_color(230, 237, 243)
    pdf.cell(0, 10, pdf.safe("Executive GRC Compliance Report"), ln=1)

    pdf.set_x(14)
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(139, 148, 158)
    pdf.cell(0, 7, pdf.safe(f"Organisation: {org_name}"), ln=1)

    pdf.set_x(14)
    pdf.cell(0, 7, pdf.safe(f"Report Date : {datetime.datetime.utcnow().strftime('%d %B %Y')}"), ln=1)
    pdf.ln(14)

    # ── Executive Summary ────────────────────────
    pdf.section_title("1.  Executive Summary")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(200, 210, 220)

    grade      = "adequate" if score >= 75 else ("requires targeted improvement" if score >= 50 else "critically deficient")
    posture_ln = (
        f"{org_name}'s current compliance posture scores {score}%, which is classified as {grade} "
        f"against ISO 27001:2022 and SOC 2 Type II benchmarks. "
        f"The automated scan identified {len(df)} open findings across {df['Asset_Name'].nunique()} assets, "
        f"of which {len(criticals)} are rated Critical and {len(highs)} High severity. "
        f"Estimated financial exposure from unmitigated risk stands at "
        f"USD {total_exposure:,.0f}. "
        f"Immediate remediation of Critical findings is mandatory to reduce inherent risk scores "
        f"and achieve sustained compliance. "
        f"This report presents a prioritised remediation roadmap aligned to the applicable control frameworks."
    )
    pdf.multi_cell(0, 6, pdf.safe(posture_ln))
    pdf.ln(4)

    # ── Compliance Score Gauge ───────────────────
    pdf.section_title("2.  Compliance Readiness Score")
    pdf.score_gauge(score)

    # ── Key Metrics ─────────────────────────────
    pdf.section_title("3.  Key Risk Metrics")
    pdf.set_font("Helvetica", "", 10)

    metrics = [
        ("Total Findings",          str(len(df))),
        ("Critical Severity",       str(len(criticals))),
        ("High Severity",           str(len(highs))),
        ("Assets Affected",         str(df["Asset_Name"].nunique())),
        ("Financial Exposure (USD)", f"${total_exposure:,.0f}"),
        ("Control Domains Breached", str(df["Control_Mapping"].nunique())),
    ]

    col_w = 92
    for idx, (label, value) in enumerate(metrics):
        x = 10 + (idx % 2) * col_w
        y = pdf.get_y()
        if idx % 2 == 0 and idx > 0:
            pdf.ln(12)
        pdf.set_xy(x, pdf.get_y())
        pdf.set_fill_color(22, 27, 34)
        pdf.rect(x, pdf.get_y(), col_w - 4, 10, "F")
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(139, 148, 158)
        pdf.set_xy(x + 2, pdf.get_y() + 1)
        pdf.cell(col_w - 6, 4, pdf.safe(label.upper()), ln=0)
        pdf.set_xy(x + 2, pdf.get_y() + 4)
        pdf.set_font("Helvetica", "B", 12)
        pdf.set_text_color(230, 237, 243)
        pdf.cell(col_w - 6, 5, pdf.safe(str(value)), ln=(1 if idx % 2 == 1 else 0))

    pdf.ln(14)

    # ── Critical Findings Table ──────────────────
    pdf.section_title("4.  Critical & High Severity Findings")
    critical_high = df[df["Severity"].isin(["Critical", "High"])].head(20)

    # Table header
    col_widths = [20, 35, 55, 22, 55]
    headers    = ["Asset ID", "Asset Name", "Vulnerability", "Severity", "Control Mapping"]
    pdf.set_font("Helvetica", "B", 8)
    pdf.set_fill_color(28, 33, 40)
    pdf.set_text_color(139, 148, 158)
    for w, h in zip(col_widths, headers):
        pdf.cell(w, 7, pdf.safe(h), border=1, fill=True)
    pdf.ln()

    pdf.set_font("Helvetica", "", 7.5)
    for _, row in critical_high.iterrows():
        pdf.set_fill_color(22, 27, 34)
        # Colour-code the severity cell
        sev = row["Severity"]
        vals = [
            row["Asset_ID"],
            row["Asset_Name"],
            row["Vulnerability"][:38] + ("..." if len(row["Vulnerability"]) > 38 else ""),
            sev,
            row["Control_Mapping"][:38] + ("..." if len(row["Control_Mapping"]) > 38 else ""),
        ]
        for i, (w, v) in enumerate(zip(col_widths, vals)):
            if i == 3:  # Severity
                if sev == "Critical":
                    pdf.set_text_color(248, 81, 73)
                else:
                    pdf.set_text_color(240, 136, 62)
            else:
                pdf.set_text_color(200, 210, 220)
            pdf.cell(w, 6, pdf.safe(str(v)), border=1, fill=True)
        pdf.ln()
        pdf.set_text_color(200, 210, 220)

    pdf.ln(6)

    # ── Control Gap Analysis ─────────────────────
    pdf.section_title("5.  Control Gap Analysis")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(200, 210, 220)

    for control, count in top_controls.items():
        short = control.split("-")[0].strip()
        desc  = CONTROL_DESCRIPTIONS.get(control, "Refer to full control documentation.")
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(88, 166, 255)
        pdf.cell(0, 6, pdf.safe(f"{short}  ({count} findings)"), ln=1)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(200, 210, 220)
        pdf.multi_cell(0, 5, pdf.safe(desc))
        pdf.ln(2)

    # ── Remediation Roadmap ──────────────────────
    pdf.section_title("6.  Prioritised Remediation Action Plan")
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(200, 210, 220)

    actions = [
        ("P1 - IMMEDIATE (0-14 days)",
         "Rotate all default credentials and enforce MFA on all externally facing services. "
         "Disable Telnet (port 23) and enforce SSH key-based authentication only. "
         "Apply emergency patches for all Critical CVEs (Log4Shell, MS17-010, and RCE vectors)."),
        ("P2 - SHORT-TERM (15-45 days)",
         "Upgrade TLS to 1.3 on all endpoints and disable deprecated cipher suites. "
         "Replace all cleartext protocols (FTP, HTTP, SMTP AUTH) with encrypted equivalents. "
         "Conduct a full port audit; close all non-business-essential open ports."),
        ("P3 - MEDIUM-TERM (46-90 days)",
         "Establish a vulnerability management lifecycle with automated scanning cadence. "
         "Integrate vulnerability feeds with ITSM ticketing for SLA-driven remediation. "
         "Conduct tabletop exercises for scenarios aligned to the Critical findings above."),
        ("P4 - GOVERNANCE (90-180 days)",
         "Formalise an ISO 27001:2022 ISMS scope and complete Statement of Applicability (SoA). "
         "Commission an external SOC 2 Type II readiness assessment. "
         "Schedule quarterly GRC dashboard reviews at executive and board level."),
    ]

    for priority, text in actions:
        pdf.set_font("Helvetica", "B", 9)
        pdf.set_text_color(63, 185, 80 if "P1" not in priority else 248)
        # Colour by priority
        if "P1" in priority:
            pdf.set_text_color(248, 81, 73)
        elif "P2" in priority:
            pdf.set_text_color(240, 136, 62)
        elif "P3" in priority:
            pdf.set_text_color(210, 153, 34)
        else:
            pdf.set_text_color(88, 166, 255)
        pdf.cell(0, 6, pdf.safe(priority), ln=1)
        pdf.set_font("Helvetica", "", 9)
        pdf.set_text_color(200, 210, 220)
        pdf.multi_cell(0, 5, pdf.safe(text))
        pdf.ln(3)

    # ── Disclaimer ───────────────────────────────
    pdf.ln(4)
    pdf.set_font("Helvetica", "I", 7.5)
    pdf.set_text_color(100, 110, 120)
    pdf.multi_cell(0, 4,
        pdf.safe("DISCLAIMER: This report is generated automatically by the Enterprise GRC Automation Dashboard. "
        "It is intended for internal risk management purposes only and does not constitute legal, "
        "audit, or certification advice. Results should be reviewed by a qualified GRC professional "
        "before use in formal compliance submissions."))

    return bytes(pdf.output())


# ──────────────────────────────────────────────
# SIDEBAR
# ──────────────────────────────────────────────
with st.sidebar:
    st.markdown(f"""
    <div style='padding:8px 0 16px; border-bottom:1px solid {BORDER}; margin-bottom:16px;'>
        <div style='font-size:20px; font-weight:700; color:{ACCENT_BLUE};'>🛡️ GRC Dashboard</div>
        <div style='font-size:11px; color:{TEXT_MUTED}; margin-top:2px;'>ISO 27001:2022 · SOC 2 · NIST</div>
    </div>
    """, unsafe_allow_html=True)

    org_name = st.text_input("Organisation Name", value="Acme Corporation",
                              help="Used in the PDF report header.")

    st.markdown(f"<div style='font-size:12px; color:{TEXT_MUTED}; margin:14px 0 6px; font-weight:600; letter-spacing:.06em; text-transform:uppercase;'>Data Source</div>", unsafe_allow_html=True)
    uploaded_file = st.file_uploader(
        "Upload vulnerability CSV",
        type=["csv"],
        help="Expected columns: Asset_ID, Asset_Name, Vulnerability, Severity, IP_Address, Port"
    )

    st.markdown(f"<div style='font-size:12px; color:{TEXT_MUTED}; margin:14px 0 6px; font-weight:600; letter-spacing:.06em; text-transform:uppercase;'>Filters</div>", unsafe_allow_html=True)
    severity_filter  = st.multiselect("Severity", ["Critical", "High", "Medium", "Low"],
                                       default=["Critical", "High", "Medium", "Low"])
    category_options = list(ASSET_CATEGORIES.values())
    category_options = sorted(set(category_options)) + ["General IT"]
    category_filter  = st.multiselect("Asset Category", category_options, default=category_options)

    st.markdown("---")
    st.markdown(f"""
    <div style='font-size:11px; color:{TEXT_MUTED}; line-height:1.6;'>
        <b style='color:{TEXT_PRIMARY};'>Frameworks Covered</b><br>
        • ISO/IEC 27001:2022<br>
        • SOC 2 (CC6 series)<br>
        • NIST SP 800-53<br><br>
        <b style='color:{TEXT_PRIMARY};'>Version</b> 1.0.0
    </div>
    """, unsafe_allow_html=True)


# ──────────────────────────────────────────────
# LOAD & ENRICH DATA
# ──────────────────────────────────────────────
if uploaded_file is not None:
    try:
        raw_df = pd.read_csv(uploaded_file)
        required = {"Asset_ID", "Asset_Name", "Vulnerability", "Severity", "IP_Address", "Port"}
        missing  = required - set(raw_df.columns)
        if missing:
            st.error(f"Uploaded CSV is missing required columns: {missing}")
            st.stop()
        using_mock = False
    except Exception as exc:
        st.error(f"Failed to parse uploaded CSV: {exc}")
        st.stop()
else:
    raw_df     = generate_mock_data(30)
    using_mock = True

df_full = enrich_dataframe(raw_df)

# Apply sidebar filters
df = df_full[
    df_full["Severity"].isin(severity_filter) &
    df_full["Asset_Category"].isin(category_filter)
].copy()


# ──────────────────────────────────────────────
# MAIN CONTENT
# ──────────────────────────────────────────────

# ── Page heading ─────────────────────────────
st.markdown(f"""
<div style='padding:6px 0 18px;'>
    <div style='font-size:24px; font-weight:700; color:{TEXT_PRIMARY};'>
        Enterprise GRC & Compliance Automation Dashboard
    </div>
    <div style='font-size:13px; color:{TEXT_MUTED}; margin-top:4px;'>
        {org_name} &nbsp;·&nbsp; {datetime.datetime.utcnow().strftime('%d %B %Y, %H:%M UTC')}
        {"&nbsp;·&nbsp; <span style='color:#58A6FF;'>⚡ Using Mock Dataset</span>" if using_mock else ""}
    </div>
</div>
""", unsafe_allow_html=True)

if using_mock:
    st.info("📋  No CSV uploaded — showing built-in mock dataset of 30 vulnerabilities across 10 assets. Upload your own scan file in the sidebar.", icon="ℹ️")

# ── Computed KPIs ──────────────────────────────
score          = compliance_score(df)
total_assets   = df["Asset_Name"].nunique()
critical_count = (df["Severity"] == "Critical").sum()
total_exposure = int(df["Financial_Exposure"].sum())
sc             = score_color(score)

# ── Metric Cards ──────────────────────────────
c1, c2, c3, c4 = st.columns(4)

with c1:
    st.markdown(f"""
    <div class='metric-card blue'>
        <div class='metric-label'>Assets Tracked</div>
        <div class='metric-value'>{total_assets}</div>
        <div class='metric-sub'>{len(df)} total findings</div>
    </div>""", unsafe_allow_html=True)

with c2:
    st.markdown(f"""
    <div class='metric-card red'>
        <div class='metric-label'>Critical Risks Found</div>
        <div class='metric-value'>{critical_count}</div>
        <div class='metric-sub'>{(df["Severity"]=="High").sum()} High severity</div>
    </div>""", unsafe_allow_html=True)

with c3:
    score_label = "Adequate" if score >= 75 else ("Needs Improvement" if score >= 50 else "At Risk")
    card_cls    = "green" if score >= 75 else ("orange" if score >= 50 else "red")
    st.markdown(f"""
    <div class='metric-card {card_cls}'>
        <div class='metric-label'>Compliance Readiness</div>
        <div class='metric-value' style='color:{sc};'>{score}%</div>
        <div class='metric-sub'>{score_label} — ISO 27001 / SOC 2</div>
    </div>""", unsafe_allow_html=True)

with c4:
    st.markdown(f"""
    <div class='metric-card orange'>
        <div class='metric-label'>Financial Exposure</div>
        <div class='metric-value'>${total_exposure:,.0f}</div>
        <div class='metric-sub'>Estimated unmitigated risk</div>
    </div>""", unsafe_allow_html=True)

st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)

# ── Row 1: Heat Matrix + Donut ─────────────────
st.markdown(f"""
<div class='section-header'>
    <span class='section-title'>Risk Visualisations</span>
    <span class='section-badge'>LIVE</span>
</div>""", unsafe_allow_html=True)

col_heat, col_donut = st.columns([3, 1.3])
with col_heat:
    st.plotly_chart(build_heat_matrix(df), use_container_width=True, config={"displayModeBar": False})
with col_donut:
    st.plotly_chart(build_severity_donut(df), use_container_width=True, config={"displayModeBar": False})

# ── Row 2: Control Gap + Inherent vs Residual ──
col_gap, col_ivr = st.columns(2)
with col_gap:
    st.plotly_chart(build_control_gap_chart(df), use_container_width=True, config={"displayModeBar": False})
with col_ivr:
    st.plotly_chart(build_inherent_vs_residual(df), use_container_width=True, config={"displayModeBar": False})

# ── Compliance Domain Progress Bars ────────────
st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
st.markdown(f"""
<div class='section-header'>
    <span class='section-title'>Compliance Domain Readiness</span>
    <span class='section-badge'>ISO 27001 · SOC 2</span>
</div>""", unsafe_allow_html=True)

domain_findings = df["Control_Mapping"].value_counts()
max_findings    = domain_findings.max() if len(domain_findings) > 0 else 1

domain_cols = st.columns(2)
for idx, (control, count) in enumerate(domain_findings.items()):
    # Invert: more findings = lower readiness
    readiness = max(0, 100 - int((count / max(df["Control_Mapping"].value_counts().sum(), 1)) * 100 * 3))
    readiness = min(readiness, 99)
    bar_color = score_color(readiness)
    short_name = control.split("-")[-1].strip() if "-" in control else control[:40]
    with domain_cols[idx % 2]:
        st.markdown(f"""
        <div style='background:{CARD_BG}; border:1px solid {BORDER}; border-radius:10px;
                    padding:14px 18px; margin-bottom:10px;'>
            <div style='display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;'>
                <span style='font-size:12px; color:{TEXT_MUTED}; max-width:75%;'>{short_name}</span>
                <span style='font-size:14px; font-weight:700; color:{bar_color};'>{readiness}%</span>
            </div>
            <div style='font-size:11px; color:{TEXT_MUTED}; margin-bottom:6px;'>{count} open finding{"s" if count != 1 else ""}</div>
            <div class='compliance-bar-wrap'>
                <div class='compliance-bar-fill' style='width:{readiness}%; background:{bar_color};'></div>
            </div>
        </div>
        """, unsafe_allow_html=True)

# ── Findings Table ─────────────────────────────
st.markdown("<div style='height:10px'></div>", unsafe_allow_html=True)
st.markdown(f"""
<div class='section-header'>
    <span class='section-title'>All Findings — GRC Mapped</span>
    <span class='section-badge'>{len(df)} records</span>
</div>""", unsafe_allow_html=True)

# Build HTML table
table_html = """<table class='grc-table'>
<thead><tr>
    <th>Asset ID</th>
    <th>Asset Name</th>
    <th>Category</th>
    <th>Vulnerability</th>
    <th>Severity</th>
    <th>IP Address</th>
    <th>Port</th>
    <th>Control Mapping</th>
    <th>Inherent Risk</th>
    <th>Residual Risk</th>
</tr></thead><tbody>
"""
for _, row in df.iterrows():
    sev = row["Severity"]
    table_html += f"""
    <tr>
        <td>{row['Asset_ID']}</td>
        <td>{row['Asset_Name']}</td>
        <td>{row['Asset_Category']}</td>
        <td>{row['Vulnerability']}</td>
        <td><span class='sev-badge sev-{sev}'>{sev}</span></td>
        <td><code style='font-size:11px; color:{TEXT_MUTED};'>{row['IP_Address']}</code></td>
        <td><code style='font-size:11px; color:{TEXT_MUTED};'>{row['Port']}</code></td>
        <td style='font-size:11px; color:{TEXT_MUTED};'>{row['Control_Mapping']}</td>
        <td style='font-weight:600; color:{ACCENT_RED};'>{row['Inherent_Risk']:.0f}</td>
        <td style='font-weight:600; color:{ACCENT_BLUE};'>{row['Residual_Risk']:.1f}</td>
    </tr>"""
table_html += "</tbody></table>"

st.markdown(
    f"<div style='overflow-x:auto; background:{CARD_BG}; border:1px solid {BORDER}; border-radius:12px; padding:4px;'>"
    + table_html + "</div>",
    unsafe_allow_html=True
)

# ── PDF Export ────────────────────────────────
st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
st.markdown(f"""
<div class='section-header'>
    <span class='section-title'>Executive PDF Report</span>
    <span class='section-badge'>PREMIUM</span>
</div>""", unsafe_allow_html=True)

st.markdown(f"""
<div style='background:{CARD_BG}; border:1px solid {BORDER}; border-radius:12px; padding:20px 24px; margin-bottom:16px;'>
    <div style='font-size:14px; color:{TEXT_PRIMARY}; font-weight:600; margin-bottom:8px;'>📄 Compile & Download Report</div>
    <div style='font-size:13px; color:{TEXT_MUTED}; line-height:1.6;'>
        Generates a corporate-grade PDF containing: executive summary, compliance score gauge,
        key risk metrics, critical findings table, control gap analysis, and a prioritised
        4-phase remediation roadmap — ready to present to the Board or an external auditor.
    </div>
</div>""", unsafe_allow_html=True)

col_btn, col_info = st.columns([1, 3])
with col_btn:
    if st.button("⚙️  Generate PDF Report", use_container_width=True):
        with st.spinner("Compiling executive report…"):
            pdf_bytes = generate_pdf_report(df_full, score, org_name)
        st.session_state["pdf_bytes"] = pdf_bytes
        st.success("Report compiled successfully!")

if "pdf_bytes" in st.session_state:
    filename = f"GRC_Report_{org_name.replace(' ','_')}_{datetime.date.today()}.pdf"
    st.download_button(
        label="⬇️  Download Executive PDF Report",
        data=st.session_state["pdf_bytes"],
        file_name=filename,
        mime="application/pdf",
        use_container_width=False,
    )
    with col_info:
        st.markdown(f"""
        <div style='background:rgba(63,185,80,0.08); border:1px solid rgba(63,185,80,0.25);
                    border-radius:8px; padding:12px 16px; margin-top:4px;'>
            <span style='color:{ACCENT_GREEN}; font-size:13px;'>✓ Report ready — click the download button to save as PDF</span>
        </div>""", unsafe_allow_html=True)

# ── Footer ─────────────────────────────────────
st.markdown("<div style='height:40px'></div>", unsafe_allow_html=True)
st.markdown(f"""
<div style='text-align:center; padding:20px; border-top:1px solid {BORDER};
            color:{TEXT_MUTED}; font-size:11px; letter-spacing:0.04em;'>
    ENTERPRISE GRC & COMPLIANCE AUTOMATION DASHBOARD &nbsp;·&nbsp;
    ISO 27001:2022 · SOC 2 · NIST SP 800-53 &nbsp;·&nbsp;
    For internal risk management purposes only
</div>""", unsafe_allow_html=True)
