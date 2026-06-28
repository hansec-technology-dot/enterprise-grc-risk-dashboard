import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import random
import io
import base64
from fpdf import FPDF

# -------------------------------
# 1. CONFIG & SESSION STATE
# -------------------------------
st.set_page_config(page_title="Enterprise GRC & Compliance Automation", layout="wide")

if 'data' not in st.session_state:
    st.session_state.data = None
if 'statuses' not in st.session_state:
    st.session_state.statuses = {}
if 'tickets' not in st.session_state:
    st.session_state.tickets = []
if 'asset_values' not in st.session_state:
    st.session_state.asset_values = {}
if 'ale_total' not in st.session_state:
    st.session_state.ale_total = 0.0

# -------------------------------
# 2. GRC MAPPING ENGINE
# -------------------------------
def map_vulnerability(vuln_text):
    vuln_lower = vuln_text.lower()
    controls = []
    if any(k in vuln_lower for k in ['credential', 'brute force', 'authentication']):
        controls.append("SOC 2 CC6.1 / ISO 27001 A.8.20")
    if any(k in vuln_lower for k in ['ssl', 'tls', 'unencrypted', 'cleartext']):
        controls.append("ISO 27001 A.8.24 / SOC 2 CC6.3")
    if any(k in vuln_lower for k in ['patch', 'outdated', 'old version', 'rce']):
        controls.append("ISO 27001 A.8.19")
    if any(k in vuln_lower for k in ['open port', 'ssh', 'telnet']):
        controls.append("ISO 27001 A.8.20")
    if not controls:
        controls.append("NIST SP 800-53 (General Risk)")
    return controls

# -------------------------------
# 3. DATA LOADING / MOCK
# -------------------------------
@st.cache_data
def load_sample_data():
    assets = [
        {"Asset_ID": i, "Asset_Name": f"Server-{i}", "IP_Address": f"192.168.1.{i}",
         "Port": random.choice([22, 80, 443, 3306, 8080]),
         "Vulnerability": random.choice([
             "Unencrypted credentials in log", "SSL/TLS weak cipher", "Missing patch for RCE",
             "Open SSH port", "Brute force possible", "Outdated Apache version",
             "Cleartext password transmission", "Telnet enabled"
         ]),
         "Severity": random.choices(["Critical","High","Medium","Low"], weights=[0.15,0.35,0.35,0.15])[0]
        } for i in range(1, 31)
    ]
    df = pd.DataFrame(assets)
    # add mapping column
    df['Mapped_Controls'] = df['Vulnerability'].apply(map_vulnerability)
    df['Status'] = 'Draft'  # initial status
    return df

def load_data():
    uploaded_file = st.sidebar.file_uploader("Upload Vulnerability Scan CSV", type=["csv"])
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        # ensure required columns
        required = ['Asset_ID','Asset_Name','Vulnerability','Severity','IP_Address','Port']
        for col in required:
            if col not in df.columns:
                st.error(f"Missing column: {col}")
                return None
        df['Mapped_Controls'] = df['Vulnerability'].apply(map_vulnerability)
        df['Status'] = 'Draft'
        return df
    else:
        st.sidebar.info("No file uploaded. Using mock dataset.")
        return load_sample_data()

# -------------------------------
# 4. QUANTITATIVE RISK ENGINE
# -------------------------------
def compute_risk_metrics(df, asset_values):
    severity_factor = {'Critical': 0.9, 'High': 0.7, 'Medium': 0.5, 'Low': 0.3}
    aro_map = {'Critical': 3, 'High': 2, 'Medium': 1, 'Low': 0.5}
    total_ale = 0.0
    risks = []
    for idx, row in df.iterrows():
        asset_id = row['Asset_ID']
        val = asset_values.get(asset_id, 50000)  # default asset value
        severity = row['Severity']
        ef = severity_factor.get(severity, 0.5)
        aro = aro_map.get(severity, 1)
        sle = val * ef
        ale = sle * aro
        total_ale += ale
        risks.append({
            'Asset_ID': asset_id,
            'Severity': severity,
            'SLE': sle,
            'ARO': aro,
            'ALE': ale
        })
    return total_ale, pd.DataFrame(risks)

# -------------------------------
# 5. PDF GENERATION
# -------------------------------
class PDF(FPDF):
    def header(self):
        self.set_font('Arial', 'B', 16)
        self.cell(0, 10, 'Enterprise GRC Executive Report', 0, 1, 'C')
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

def generate_pdf(df, total_ale, tickets):
    pdf = PDF()
    pdf.add_page()
    pdf.set_font('Arial', '', 12)
    # Summary
    pdf.cell(0, 10, 'Compliance Posture Summary', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    summary = f"Total assets: {len(df)}. Total financial exposure: ${total_ale:,.2f}. " \
              f"Open tickets: {len(tickets)}. Critical vulnerabilities: {len(df[df['Severity']=='Critical'])}."
    pdf.multi_cell(0, 8, summary)
    pdf.ln(5)

    # Critical failures table
    critical_df = df[df['Severity'].isin(['Critical','High'])]
    if not critical_df.empty:
        pdf.set_font('Arial', 'B', 10)
        pdf.cell(40, 10, 'Asset', 1)
        pdf.cell(60, 10, 'Vulnerability', 1)
        pdf.cell(30, 10, 'Severity', 1)
        pdf.cell(60, 10, 'Mapped Controls', 1)
        pdf.ln()
        pdf.set_font('Arial', '', 9)
        for _, row in critical_df.iterrows():
            pdf.cell(40, 8, str(row['Asset_Name']), 1)
            pdf.cell(60, 8, row['Vulnerability'][:30], 1)
            pdf.cell(30, 8, row['Severity'], 1)
            controls = ', '.join(row['Mapped_Controls']) if isinstance(row['Mapped_Controls'], list) else row['Mapped_Controls']
            pdf.cell(60, 8, controls[:30], 1)
            pdf.ln()
    pdf.ln(5)

    # Remediation steps
    pdf.set_font('Arial', 'B', 10)
    pdf.cell(0, 10, 'Recommended Remediation Actions', 0, 1, 'L')
    pdf.set_font('Arial', '', 10)
    for i, ticket in enumerate(tickets[:5], 1):
        pdf.cell(0, 6, f"{i}. {ticket['description']} (Owner: {ticket['owner']}, Due: {ticket['due_date']})", 0, 1)
    if not tickets:
        pdf.cell(0, 6, "No open remediation tickets. All controls passed.", 0, 1)

    # Return as bytes
    pdf_output = pdf.output(dest='S').encode('latin-1')
    return pdf_output

# -------------------------------
# 6. STREAMLIT UI
# -------------------------------
def main():
    st.title("🔐 Enterprise GRC & Compliance Automation Dashboard")
    st.caption("ISO 27001:2022 & SOC 2 Compliance Bridge")

    # Sidebar
    st.sidebar.header("Data & Filters")
    df = load_data()
    if df is None:
        st.stop()
    # store in session
    st.session_state.data = df.copy()

    # Initialize statuses from df if not set
    if not st.session_state.statuses:
        st.session_state.statuses = {row['Asset_ID']: row['Status'] for _, row in df.iterrows()}

    # Initialize asset values (if not set)
    if not st.session_state.asset_values:
        for asset_id in df['Asset_ID'].unique():
            st.session_state.asset_values[asset_id] = 50000  # default

    # Filters
    severity_filter = st.sidebar.multiselect("Severity", options=df['Severity'].unique(), default=df['Severity'].unique())
    asset_filter = st.sidebar.multiselect("Asset Category", options=df['Asset_Name'].unique(), default=df['Asset_Name'].unique())
    filtered_df = df[(df['Severity'].isin(severity_filter)) & (df['Asset_Name'].isin(asset_filter))]

    # Recompute metrics on filtered data
    total_ale, risk_df = compute_risk_metrics(filtered_df, st.session_state.asset_values)
    st.session_state.ale_total = total_ale

    # Tabs
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(
        ["📊 Overview", "🔥 Risk Heat Matrix", "📉 Compliance Gaps", "💰 Financial Risk",
         "🔄 Lifecycle Simulator", "🎫 Remediation Tickets"])

    # ----- TAB 1: Overview -----
    with tab1:
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Assets Tracked", len(filtered_df))
        col2.metric("Critical Risks Found", len(filtered_df[filtered_df['Severity']=='Critical']))
        # Compliance readiness: percentage of assets with status not in 'Draft'? or based on mapping?
        # For simplicity, assume compliance if status != 'Draft' and severity not Critical? Let's define: if vulnerability has been assessed (status in ['Assess','Respond','Review','Monitor']) and severity is Low or Medium, considered compliant.
        compliant = filtered_df[(~filtered_df['Status'].isin(['Draft','Assess'])) & (filtered_df['Severity'].isin(['Low','Medium']))]
        readiness = len(compliant) / len(filtered_df) * 100 if len(filtered_df)>0 else 0
        col3.metric("Compliance Readiness", f"{readiness:.1f}%")
        col4.metric("Total Financial Exposure", f"${total_ale:,.0f}")

        st.subheader("Recent Vulnerabilities")
        st.dataframe(filtered_df[['Asset_ID','Asset_Name','Vulnerability','Severity','Status']].head(10), use_container_width=True)

    # ----- TAB 2: Risk Heat Matrix -----
    with tab2:
        st.subheader("5x5 Risk Heat Matrix (Likelihood vs Impact)")
        # Construct likelihood and impact from severity
        severity_to_likelihood = {'Critical':5, 'High':4, 'Medium':3, 'Low':2}  # 1-5 scale
        severity_to_impact = {'Critical':5, 'High':4, 'Medium':3, 'Low':2}
        heat_data = filtered_df.copy()
        heat_data['Likelihood'] = heat_data['Severity'].map(severity_to_likelihood)
        heat_data['Impact'] = heat_data['Severity'].map(severity_to_impact)
        # Group by Likelihood and Impact
        heat_counts = heat_data.groupby(['Likelihood','Impact']).size().reset_index(name='count')
        # Create matrix
        matrix = np.zeros((5,5))
        for _, row in heat_counts.iterrows():
            matrix[row['Likelihood']-1][row['Impact']-1] = row['count']

        fig = go.Figure(data=go.Heatmap(
            z=matrix,
            x=['1','2','3','4','5'],
            y=['5','4','3','2','1'],
            colorscale='RdYlGn_r',
            text=matrix,
            texttemplate='%{text}',
            textfont={"size": 12},
            hoverongaps=False))
        fig.update_layout(height=500, width=700, xaxis_title="Impact", yaxis_title="Likelihood")
        st.plotly_chart(fig, use_container_width=True)

    # ----- TAB 3: Compliance Gaps -----
    with tab3:
        st.subheader("Compliance Gaps per Control")
        # Get all unique controls from mapped columns
        all_controls = set()
        for controls in filtered_df['Mapped_Controls']:
            if isinstance(controls, list):
                all_controls.update(controls)
            else:
                all_controls.add(controls)
        all_controls = sorted(all_controls)

        # Determine compliance: if any vulnerability mapped to that control has severity Critical or High and status not 'Resolved', mark as gap
        gap_status = {}
        for control in all_controls:
            # vulnerabilities with this control
            vulns = filtered_df[filtered_df['Mapped_Controls'].apply(lambda x: control in x if isinstance(x, list) else x == control)]
            if vulns.empty:
                gap_status[control] = "No Data"
            else:
                # check if any critical/high and not resolved
                unresolved = vulns[(vulns['Severity'].isin(['Critical','High'])) & (vulns['Status'] != 'Resolved')]
                if not unresolved.empty:
                    gap_status[control] = "Gap"
                else:
                    gap_status[control] = "Compliant"

        # Bar chart
        gap_df = pd.DataFrame(list(gap_status.items()), columns=['Control', 'Status'])
        fig = px.bar(gap_df, x='Control', y='Status', color='Status',
                     color_discrete_map={'Gap':'red', 'Compliant':'green', 'No Data':'grey'},
                     title="Control Compliance Status")
        st.plotly_chart(fig, use_container_width=True)

        # Add "Execute Compliance Test" buttons
        st.subheader("Control Testing Loop")
        for control in all_controls[:10]:  # limit for UI
            col1, col2 = st.columns([3,1])
            col1.write(f"**{control}**")
            if col2.button(f"Test {control}", key=f"test_{control}"):
                # Check if any vulnerability mapped to this control is unresolved
                vulns = filtered_df[filtered_df['Mapped_Controls'].apply(lambda x: control in x if isinstance(x, list) else x == control)]
                unresolved = vulns[(vulns['Severity'].isin(['Critical','High'])) & (vulns['Status'] != 'Resolved')]
                if not unresolved.empty:
                    # create ticket
                    ticket = {
                        'id': f"ISSUE-{len(st.session_state.tickets)+1:04d}",
                        'control': control,
                        'description': f"Implement remediation for {control} - {unresolved.iloc[0]['Vulnerability']}",
                        'owner': 'Cybersecurity Manager',
                        'due_date': (datetime.now() + timedelta(days=30)).strftime('%Y-%m-%d'),
                        'status': 'Open'
                    }
                    st.session_state.tickets.append(ticket)
                    st.success(f"Ticket {ticket['id']} generated! (FAILED)")
                else:
                    st.success("Test PASSED - No unresolved vulnerabilities for this control.")

    # ----- TAB 4: Financial Risk -----
    with tab4:
        st.subheader("Quantitative Risk Assessment")
        st.write("Adjust asset values below to compute Annualized Loss Expectancy (ALE).")
        # Asset value input
        asset_ids = filtered_df['Asset_ID'].unique()
        for asset_id in asset_ids:
            val = st.number_input(f"Asset {asset_id} Value ($)", min_value=0, value=int(st.session_state.asset_values.get(asset_id, 50000)), step=1000, key=f"val_{asset_id}")
            st.session_state.asset_values[asset_id] = val

        # Recompute with updated values
        total_ale, risk_df = compute_risk_metrics(filtered_df, st.session_state.asset_values)
        st.session_state.ale_total = total_ale

        col1, col2, col3 = st.columns(3)
        col1.metric("Total Annualized Loss (ALE)", f"${total_ale:,.2f}")
        col2.metric("Total Asset Value", f"${sum(st.session_state.asset_values.values()):,.2f}")
        col3.metric("Exposure Factor (Avg)", f"{total_ale / sum(st.session_state.asset_values.values()) if sum(st.session_state.asset_values.values())>0 else 0:.2%}")

        st.dataframe(risk_df, use_container_width=True)

        # Visual
        fig = px.bar(risk_df, x='Asset_ID', y='ALE', color='Severity', title="ALE per Asset")
        st.plotly_chart(fig, use_container_width=True)

    # ----- TAB 5: Lifecycle Simulator -----
    with tab5:
        st.subheader("Risk Lifecycle (ServiceNow-style)")
        st.write("Change status of each vulnerability to simulate workflow.")

        # Create a copy of filtered df for editing
        edit_df = filtered_df.copy()
        # Use session state statuses
        status_options = ['Draft', 'Assess', 'Respond', 'Review', 'Monitor', 'Resolved']

        # Display table with dropdowns
        for idx, row in edit_df.iterrows():
            asset_id = row['Asset_ID']
            current_status = st.session_state.statuses.get(asset_id, 'Draft')
            new_status = st.selectbox(
                f"{row['Asset_Name']} - {row['Vulnerability'][:30]}",
                options=status_options,
                index=status_options.index(current_status) if current_status in status_options else 0,
                key=f"status_{asset_id}"
            )
            if new_status != current_status:
                st.session_state.statuses[asset_id] = new_status
                # Update df status column
                df.loc[df['Asset_ID'] == asset_id, 'Status'] = new_status
                st.experimental_rerun()

        # Show status distribution
        status_counts = pd.Series(st.session_state.statuses).value_counts().reset_index()
        status_counts.columns = ['Status', 'Count']
        fig = px.bar(status_counts, x='Status', y='Count', title="Status Distribution")
        st.plotly_chart(fig, use_container_width=True)

    # ----- TAB 6: Remediation Tickets -----
    with tab6:
        st.subheader("Generated Remediation Tickets")
        if not st.session_state.tickets:
            st.info("No tickets generated yet. Run compliance tests in the Compliance Gaps tab.")
        else:
            tickets_df = pd.DataFrame(st.session_state.tickets)
            st.dataframe(tickets_df, use_container_width=True)
            # Option to resolve ticket
            for i, ticket in enumerate(st.session_state.tickets):
                if ticket['status'] == 'Open':
                    if st.button(f"Resolve {ticket['id']}", key=f"resolve_{i}"):
                        st.session_state.tickets[i]['status'] = 'Resolved'
                        st.experimental_rerun()

    # ----- Executive PDF Report -----
    st.sidebar.markdown("---")
    if st.sidebar.button("📄 Generate Executive PDF Report"):
        with st.spinner("Generating PDF..."):
            pdf_bytes = generate_pdf(filtered_df, st.session_state.ale_total, st.session_state.tickets)
            b64 = base64.b64encode(pdf_bytes).decode()
            href = f'<a href="data:application/pdf;base64,{b64}" download="GRC_Report.pdf">Download PDF Report</a>'
            st.sidebar.markdown(href, unsafe_allow_html=True)
            st.sidebar.success("PDF ready for download.")

if __name__ == "__main__":
    main()
