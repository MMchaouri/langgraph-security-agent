import json
from datetime import datetime
from pathlib import Path

import streamlit as st

from agent import graph

HISTORY_FILE = Path(__file__).parent / "history.json"

EXAMPLE_ALERTS = {
    "Phishing email": (
        "User reported a suspicious email from 'security@paypa1.com' asking to verify account. "
        "Email headers show SPF fail, DKIM invalid, sender domain registered 2 days ago. "
        "Link points to http://paypa1-verify.xyz/login"
    ),
    "Brute force SSH": (
        "47 failed SSH login attempts from IP 185.220.101.42 against user 'root' on prod-server-01 "
        "between 03:12-03:19 UTC. One successful login at 03:19 UTC."
    ),
    "Suspicious insider": (
        "User jsmith logged in from IP 192.168.1.1 at 3:14 AM on a Saturday. "
        "Accessed 200+ files in HR share within 10 minutes. No prior after-hours logins."
    ),
    "Malware download": (
        "Endpoint detection flagged process 'svchost32.exe' on workstation WIN-04 making outbound "
        "connections to 185.220.101.42:4444. File hash not in known-good database. "
        "Process spawned from chrome.exe after user visited hxxp://cdn-update[.]ru/patch.exe"
    ),
    "Credential stuffing": (
        "Auth service logged 2,300 failed login attempts across 800 unique accounts in 4 minutes. "
        "All requests originate from 185.220.101.42. Rate limiting kicked in at minute 3. "
        "12 accounts had successful logins before lockout."
    ),
    "Suspicious OAuth grant": (
        "User accepted an OAuth permission request from app 'MS Office365 Backup' requesting "
        "Mail.ReadWrite and Files.ReadWrite.All scopes. App registered 3 days ago, "
        "publisher unverified, redirect URI points to 45.33.22.11."
    ),
}


def load_history() -> list:
    if HISTORY_FILE.exists():
        return json.loads(HISTORY_FILE.read_text())
    return []


def save_to_history(alert: str, report: dict) -> None:
    history = load_history()
    history.insert(0, {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "alert_preview": alert[:80] + "..." if len(alert) > 80 else alert,
        "severity": report.get("severity", "unknown"),
        "threat_type": report.get("threat_type", "unknown"),
    })
    HISTORY_FILE.write_text(json.dumps(history[:20], indent=2))


st.set_page_config(page_title="Security Triage Agent", layout="centered")
st.title("Security Alert Triage Agent")
st.caption("Autonomous threat analysis — LangGraph + OpenAI gpt-4o-mini")

with st.sidebar:
    st.subheader("Example Alerts")
    for label, text in EXAMPLE_ALERTS.items():
        if st.button(label, use_container_width=True):
            st.session_state["alert_text"] = text

    history = load_history()
    if history:
        st.divider()
        st.subheader("Recent Analyses")
        for item in history[:5]:
            st.caption(f"{item['timestamp']} — **{item['severity'].upper()}** {item['threat_type']}")
            st.caption(f"_{item['alert_preview']}_")

    st.divider()
    with st.expander("Agent Graph (Mermaid)"):
        st.code(graph.get_graph().draw_mermaid(), language="text")
        st.caption("Paste at mermaid.live to visualize")

alert = st.text_area(
    "Paste a security alert:",
    value=st.session_state.get("alert_text", ""),
    height=160,
    placeholder="Describe a security event...",
)

if st.button("Analyze", type="primary", disabled=not alert.strip()):
    full_state = {
        "alert": alert,
        "threat_type": "",
        "tool_results": [],
        "iterations": 0,
        "done": False,
        "report": {},
    }

    with st.status("Starting analysis...") as status:
        for chunk in graph.stream(full_state):
            node_name = list(chunk.keys())[0]
            update = chunk[node_name]
            full_state.update(update)

            if node_name == "classify":
                label = f"Classified as: {update.get('threat_type', '...')}"
            elif node_name == "select_tool":
                if update.get("done"):
                    label = "Investigation complete — writing report..."
                else:
                    tool_results = update.get("tool_results", [])
                    last_tool = tool_results[-1]["tool"].replace("_", " ") if tool_results else "tool"
                    label = f"Called {last_tool}"
            elif node_name == "report":
                label = "Triage report ready"
            else:
                label = node_name

            status.update(label=label)
        status.update(label="Done", state="complete")

    report = full_state["report"]
    severity = report.get("severity", "unknown").lower()

    st.divider()

    severity_fn = {"low": st.success, "medium": st.warning, "high": st.error, "critical": st.error}
    severity_fn.get(severity, st.info)(f"Severity: {severity.upper()} — {report.get('threat_type', 'N/A')}")

    col1, col2, col3 = st.columns(3)
    col1.metric("Severity", severity.upper())
    col2.metric("Threat Type", report.get("threat_type", "N/A"))
    col3.metric("Confidence", report.get("confidence", "N/A").upper())

    st.info(f"**Recommended Action:** {report.get('recommended_action', 'N/A')}")
    st.write("**Reasoning:**", report.get("reasoning", "N/A"))

    st.download_button(
        "Download Report (JSON)",
        data=json.dumps({"alert": alert, "report": report, "tool_results": full_state["tool_results"]}, indent=2),
        file_name=f"triage_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
        mime="application/json",
    )

    with st.expander(f"Investigation trail ({full_state['iterations']} tool call(s))"):
        if full_state["tool_results"]:
            for i, call in enumerate(full_state["tool_results"], 1):
                st.markdown(f"**Step {i} — `{call['tool']}`**")
                st.write("Args:", call["args"])
                st.json(call["result"])
        else:
            st.write("No tools called — classified from alert text alone.")

    save_to_history(alert, report)
