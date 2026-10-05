import streamlit as st
import pandas as pd
import requests
import time
from io import BytesIO
import openpyxl
from openpyxl import Workbook

# Page config
st.set_page_config(
    page_title="IOC Malware Filter",
    page_icon="🔍",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Custom CSS
st.markdown("""
    <style>
    .main {
        padding: 2rem;
    }
    .stButton > button {
        width: 100%;
        height: 3rem;
        font-size: 1rem;
        font-weight: 600;
    }
    </style>
""", unsafe_allow_html=True)

# Title
st.markdown("# 🔍 IOC Malware Filter")
st.markdown("**Check IOCs with VirusTotal • Filter clean ones automatically**")

# Sidebar info
with st.sidebar:
    st.markdown("### About")
    st.markdown("""
    This tool:
    - ✅ Checks IOCs against VirusTotal (90+ vendors)
    - ✅ Automatically deletes clean IOCs
    - ✅ Works on any network
    - ✅ Free to use
    
    **Get your free API key:**
    https://www.virustotal.com
    """)

# Main layout
col1, col2 = st.columns(2)

with col1:
    st.markdown("### 🔑 VirusTotal API Key")
    api_key = st.text_input(
        "Paste your API key",
        type="password",
        label_visibility="collapsed",
        placeholder="Your VirusTotal API key"
    )
    st.caption("Never stored, only used in this session")

with col2:
    st.markdown("### 📁 Upload Excel File")
    uploaded_file = st.file_uploader(
        "Select your Excel file",
        type=['xlsx', 'xls'],
        label_visibility="collapsed"
    )

# Process button
if st.button("🚀 Check IOCs & Filter", use_container_width=True):
    if not api_key:
        st.error("❌ Please paste your VirusTotal API key")
    elif not uploaded_file:
        st.error("❌ Please select an Excel file")
    else:
        # Read Excel file
        try:
            df = pd.read_excel(uploaded_file)
            st.success(f"✅ Loaded {len(df)} IOCs")
            
            # Progress tracking
            progress_bar = st.progress(0)
            status_text = st.empty()
            results_placeholder = st.empty()
            
            # Data storage
            total_iocs = len(df)
            malicious_count = 0
            cleaned_count = 0
            results_by_sheet = {}
            
            # Get unique sheet names from original file
            excel_file = pd.ExcelFile(uploaded_file)
            sheet_names = excel_file.sheet_names
            
            # Initialize results for each sheet
            for sheet in sheet_names:
                results_by_sheet[sheet] = []
            
            # Check each IOC
            for idx, row in df.iterrows():
                if len(row) >= 1 and pd.notna(row[0]):
                    ioc = str(row[0]).strip().strip('"')
                    
                    try:
                        # Call VirusTotal API
                        url = f"https://www.virustotal.com/api/v3/search?query={ioc}"
                        headers = {'x-apikey': api_key}
                        response = requests.get(url, headers=headers, timeout=10)
                        
                        is_malicious = False
                        
                        if response.status_code == 200:
                            data = response.json()
                            if data.get('data') and len(data['data']) > 0:
                                result = data['data'][0]
                                stats = result.get('attributes', {}).get('last_analysis_stats', {})
                                malicious = stats.get('malicious', 0)
                                suspicious = stats.get('suspicious', 0)
                                is_malicious = (malicious > 0 or suspicious > 0)
                        
                        if is_malicious:
                            malicious_count += 1
                            # Add to first sheet for now (will improve later)
                            if sheet_names:
                                results_by_sheet[sheet_names[0]].append(ioc)
                        else:
                            cleaned_count += 1
                        
                    except Exception as e:
                        cleaned_count += 1
                    
                    # Update progress
                    progress = (idx + 1) / total_iocs
                    progress_bar.progress(progress)
                    status_text.write(f"Checking: {idx + 1}/{total_iocs} | Malicious: {malicious_count} | Clean: {cleaned_count}")
                    
                    # Rate limiting
                    time.sleep(0.1)
            
            # Show results
            status_text.empty()
            progress_bar.empty()
            
            results_col1, results_col2, results_col3, results_col4 = st.columns(4)
            
            with results_col1:
                st.metric("Total IOCs", total_iocs)
            with results_col2:
                st.metric("Malicious", malicious_count, delta_color="off")
            with results_col3:
                st.metric("Cleaned", cleaned_count, delta_color="off")
            with results_col4:
                st.metric("Malicious %", f"{(malicious_count/total_iocs*100):.1f}%")
            
            # Create downloadable Excel
            if malicious_count > 0:
                wb = Workbook()
                wb.remove(wb.active)
                
                for sheet_name in results_by_sheet:
                    if results_by_sheet[sheet_name]:
                        ws = wb.create_sheet(sheet_name)
                        ws['A1'] = 'ioc_value'
                        
                        for idx, ioc in enumerate(sorted(set(results_by_sheet[sheet_name])), 2):
                            ws[f'A{idx}'] = ioc
                        
                        ws.column_dimensions['A'].width = 100
                
                # Save to bytes
                output = BytesIO()
                wb.save(output)
                output.seek(0)
                
                # Download button
                st.download_button(
                    label="📥 Download Cleaned Excel",
                    data=output.getvalue(),
                    file_name="IOC_Filtered_Malicious_Only.xlsx",
                    mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                    use_container_width=True
                )
                
                st.success("✅ Scan Complete! Download your cleaned file above.")
            else:
                st.warning("⚠️ No malicious IOCs found. All IOCs appear to be clean.")
        
        except Exception as e:
            st.error(f"❌ Error: {str(e)}")
