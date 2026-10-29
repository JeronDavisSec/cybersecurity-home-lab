import re
from datetime import datetime
import subprocess
import sys
from collections import Counter
from pathlib import Path

import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Cybersecurity Operations Dashboard",
    page_icon="🔐",
    layout="wide",
)

st.markdown("""
<div style="display:flex;justify-content:space-between;align-items:center;
padding:18px 22px;margin-bottom:22px;background:#111E30;
border:1px solid #2A405A;border-left:5px solid #31D7C0;border-radius:12px;">
  <div>
    <div style="color:#31D7C0;font-size:12px;letter-spacing:3px;font-weight:700;">
      JERONDAVISSEC / SECURITY LAB
    </div>
    <h1 style="border:0;margin:8px 0 4px;padding:0;font-size:30px;">
      SENTINEL
    </h1>
    <div style="color:#9DB3CC;">Security Operations Center · SSH Monitoring</div>
  </div>
  <div style="background:#12382F;color:#65F0D8;padding:9px 13px;
  border:1px solid #247A68;border-radius:8px;font-size:12px;font-weight:700;">
    ● MONITORING ACTIVE
  </div>
</div>
""", unsafe_allow_html=True)


DEFAULT_LOG = Path("logs") / "Sample-auth.log"
TIMESTAMP_PATTERN = re.compile(
    r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
)
FAILED_PATTERN = re.compile(
    r"Failed password for (?:invalid user )?(\S+) from ([0-9A-Fa-f:.]+)"
)
SUCCESS_PATTERN = re.compile(
    r"Accepted (?:password|publickey) for (\S+) from ([0-9A-Fa-f:.]+)"
)

uploaded_file = st.file_uploader("Upload an SSH authentication log", type=["log", "txt"])
threshold = st.sidebar.slider("Failed-login alert threshold", 3, 20, 5)

if uploaded_file:
    lines = uploaded_file.getvalue().decode("utf-8", errors="replace").splitlines()
    source_name = uploaded_file.name
elif DEFAULT_LOG.exists():
    lines = DEFAULT_LOG.read_text(encoding="utf-8", errors="replace").splitlines()
    source_name = str(DEFAULT_LOG)
else:
    lines = []
    source_name = "No log selected"

if not lines:
    st.warning("No log entries found. Check that logs/Sample-auth.log exists or upload a log.")
    st.stop()

failures = Counter()
successes = Counter()
failure_times = {}
success_times = {}
events = []
current_year = datetime.now().year
previous_month = None

for line in lines:
    failed = FAILED_PATTERN.search(line)
    success = SUCCESS_PATTERN.search(line)

    if failed:
        user, ip = failed.groups()
        failures[ip] += 1
        events.append({
            "Event": "Failed login",
            "Username": user,
            "IP Address": ip,
            "Log Entry": line,
        })
    elif success:
        user, ip = success.groups()
        successes[ip] += 1
        events.append({
            "Event": "Successful login",
            "Username": user,
            "IP Address": ip,
            "Log Entry": line,
        })

suspicious_ips = {
    ip for ip, count in failures.items() if count >= threshold
}
critical_ips = suspicious_ips.intersection(successes)

col1, col2, col3, col4 = st.columns(4)
col1.metric("Failed Login Attempts", sum(failures.values()))
col2.metric("Suspicious IP Addresses", len(suspicious_ips))
col3.metric("Critical Alerts", len(critical_ips))
col4.metric("Successful Logins", sum(successes.values()))

st.caption(f"Log source: {source_name} | Entries read: {len(lines)}")
st.divider()

st.markdown("""
<div style="display:flex;align-items:center;gap:12px;margin:24px 0 14px;">
  <div style="width:4px;height:28px;background:#FF5D6C;border-radius:4px;"></div>
  <div>
    <div style="font-size:21px;font-weight:750;color:#EAF3FF;">
      Threat Detection Center
    </div>
    <div style="font-size:12px;color:#8FA7C1;">
      SSH authentication alerts · Prioritized by severity
    </div>
  </div>
</div>
""", unsafe_allow_html=True)


if critical_ips:
    for ip in sorted(critical_ips):
        st.markdown(f"""
        <div style="background:#301A27;border:1px solid #FF5D6C;
        border-left:5px solid #FF5D6C;border-radius:10px;
        padding:16px 20px;margin:12px 0;">
            <div style="color:#FF7783;font-size:12px;
            font-weight:800;letter-spacing:2px;">● CRITICAL ALERT</div>
            <div style="color:#F5F7FB;font-size:20px;
            font-weight:700;margin:8px 0;">{ip}</div>
            <div style="color:#D6BFC7;">
                {failures[ip]} failed login attempts detected, with at least
                one successful login from this IP.
            </div>
        </div>
        """, unsafe_allow_html=True)

high_ips = suspicious_ips - critical_ips
if high_ips:
    for ip in sorted(high_ips):
        st.markdown(f"""
        <div style="background:#30291A;border:1px solid #E6B450;
        border-left:5px solid #E6B450;border-radius:10px;
        padding:16px 20px;margin:12px 0;">
            <div style="color:#F2C66D;font-size:12px;
            font-weight:800;letter-spacing:2px;">▲ HIGH SEVERITY</div>
            <div style="color:#F5F7FB;font-size:20px;
            font-weight:700;margin:8px 0;">{ip}</div>
            <div style="color:#D9D0BC;">
                {failures[ip]} failed login attempts reached the configured
                alert threshold.
            </div>
        </div>
        """, unsafe_allow_html=True)

if not suspicious_ips:
    st.success("No IP addresses reached the configured failed-login threshold.")

st.divider()
st.header("📊 Authentication Activity")

if failures:
    activity = pd.DataFrame(
        [{"IP Address": ip, "Failed Attempts": count}
         for ip, count in failures.most_common()]
    )
    st.bar_chart(activity.set_index("IP Address"))

    st.subheader("Failed Login Summary")
    st.dataframe(activity, use_container_width=True, hide_index=True)
else:
    st.info("No failed login events were detected.")

st.subheader("Authentication Events")
if events:
    st.dataframe(pd.DataFrame(events), use_container_width=True, hide_index=True)
else:
    st.info("No recognized SSH authentication events were found.")

st.caption("JeronDavisSec | Cybersecurity Home Lab | Defensive log analysis")


st.divider()
st.header("🛡️ Original SSH Analyzer Report")

analyzer_path = Path("Scripts") / "log-analyzer.py"

if st.button("Run Original Analyzer", type="primary"):
    result = subprocess.run(
        [
            sys.executable,
            str(analyzer_path),
            str(DEFAULT_LOG),
            "--threshold",
            str(threshold),
        ],
        capture_output=True,
        text=True,
        cwd=Path.cwd(),
    )

    if result.returncode == 0:
        st.success("Original analyzer completed successfully.")
        st.code(result.stdout, language="text")
    else:
        st.error("The original analyzer encountered an error.")
        st.code(result.stderr or result.stdout, language="text")


st.markdown("""
<style>
    .stApp {
        background: linear-gradient(145deg, #080F1D 0%, #101B2D 55%, #0A1423 100%);
        color: #E5EDF7;
    }

    [data-testid="stHeader"] {
        background: rgba(8, 15, 29, 0.92);
    }

    [data-testid="stSidebar"] {
        background: #0C1727;
        border-right: 1px solid #24354B;
    }

    h1, h2, h3 {
        color: #EAF3FF !important;
        letter-spacing: -0.4px;
    }

    h1 {
        border-bottom: 2px solid #31D7C0;
        padding-bottom: 12px;
    }

    [data-testid="stMetric"] {
        background: linear-gradient(145deg, #17283D, #101D30);
        border: 1px solid #2A405A;
        border-radius: 14px;
        padding: 18px 20px;
        box-shadow: 0 5px 18px rgba(0, 0, 0, 0.20);
    }

    [data-testid="stMetricLabel"] {
        color: #9DB3CC !important;
        font-size: 0.85rem;
    }

    [data-testid="stMetricValue"] {
        color: #48E0C6 !important;
        font-weight: 700;
    }

    [data-testid="stAlert"] {
        border-radius: 10px;
    }

    [data-testid="stDataFrame"] {
        border: 1px solid #2A405A;
        border-radius: 10px;
        overflow: hidden;
    }

    div.stButton > button {
        background: #24CDB7;
        color: #071421;
        border: none;
        border-radius: 8px;
        font-weight: 700;
        padding: 0.6rem 1rem;
    }

    div.stButton > button:hover {
        background: #65F0D8;
        color: #071421;
        border: none;
    }

    hr {
        border-color: #293B51;
    }

    [data-testid="stCaptionContainer"] {
        color: #8FA7C1;
    }
</style>
""", unsafe_allow_html=True)

