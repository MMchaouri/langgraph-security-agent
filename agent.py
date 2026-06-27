import json
import os
import re
from typing import Optional, TypedDict

from dotenv import load_dotenv

load_dotenv()

os.environ.setdefault("SSL_CERT_FILE", os.path.join(os.path.dirname(__file__), "ClaudeBundle.pem"))
os.environ.setdefault("REQUESTS_CA_BUNDLE", os.environ["SSL_CERT_FILE"])

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_openai import ChatOpenAI
from langgraph.graph import END, StateGraph
from pydantic import BaseModel, ConfigDict

from tools import TOOLS

llm = ChatOpenAI(model="gpt-4o-mini", temperature=0)

MAX_ITERATIONS = 3


class AgentState(TypedDict):
    alert: str
    threat_type: str
    tool_results: list
    iterations: int
    done: bool
    report: dict


class ThreatClassification(BaseModel):
    model_config = ConfigDict(extra="forbid")
    threat_type: str
    reasoning: str


class ToolSelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    tool: str  # lookup_ip_reputation | check_email_headers | search_past_incidents | done
    ip: Optional[str] = None
    headers: Optional[str] = None
    query: Optional[str] = None
    reasoning: str


class TriageReport(BaseModel):
    model_config = ConfigDict(extra="forbid")
    severity: str  # low | medium | high | critical
    threat_type: str
    recommended_action: str
    reasoning: str
    confidence: str  # low | medium | high


def classify(state: AgentState) -> dict:
    result = llm.with_structured_output(ThreatClassification).invoke([
        SystemMessage("You are a security analyst. Classify the threat type of this security alert. "
                      "threat_type must be one of: phishing, brute_force, malware, suspicious_login, unknown."),
        HumanMessage(f"Alert: {state['alert']}"),
    ])
    return {"threat_type": result.threat_type}


def select_tool(state: AgentState) -> dict:
    tool_results_str = json.dumps(state["tool_results"], indent=2) if state["tool_results"] else "None yet"

    result = llm.with_structured_output(ToolSelection).invoke([
        SystemMessage(
            "You are a security analyst investigating an alert. Choose the next tool to call, "
            "or 'done' if you have sufficient context.\n\n"
            "Available tools:\n"
            "- lookup_ip_reputation: set ip field to the IP address\n"
            "- check_email_headers: set headers field to raw headers or description\n"
            "- search_past_incidents: set query field to search terms\n"
            "- done: no more tools needed"
        ),
        HumanMessage(
            f"Alert: {state['alert']}\n"
            f"Threat type: {state['threat_type']}\n"
            f"Tools used so far:\n{tool_results_str}"
        ),
    ])

    if result.tool == "done" or state["iterations"] >= MAX_ITERATIONS:
        return {"done": True}

    alert_text = state["alert"]
    if result.tool == "lookup_ip_reputation":
        ip_match = re.search(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', alert_text)
        args = {"ip": result.ip or (ip_match.group(0) if ip_match else "unknown")}
    elif result.tool == "check_email_headers":
        args = {"headers": result.headers or alert_text}
    elif result.tool == "search_past_incidents":
        args = {"query": result.query or f"{state['threat_type']} {alert_text[:100]}"}
    else:
        args = {}

    tool_fn = TOOLS.get(result.tool)
    tool_output = tool_fn(**args) if tool_fn else {"error": f"unknown tool: {result.tool}"}

    return {
        "tool_results": state["tool_results"] + [{"tool": result.tool, "args": args, "result": tool_output}],
        "iterations": state["iterations"] + 1,
        "done": False,
    }


def generate_report(state: AgentState) -> dict:
    result = llm.with_structured_output(TriageReport).invoke([
        SystemMessage("You are a security analyst. Generate a concise triage report based on the evidence collected."),
        HumanMessage(
            f"Alert: {state['alert']}\n"
            f"Threat type: {state['threat_type']}\n"
            f"Investigation results:\n{json.dumps(state['tool_results'], indent=2)}"
        ),
    ])
    return {"report": result.model_dump()}


def should_continue(state: AgentState) -> str:
    return "report" if state.get("done") else "select_tool"


builder = StateGraph(AgentState)
builder.add_node("classify", classify)
builder.add_node("select_tool", select_tool)
builder.add_node("report", generate_report)

builder.set_entry_point("classify")
builder.add_edge("classify", "select_tool")
builder.add_conditional_edges("select_tool", should_continue, {
    "select_tool": "select_tool",
    "report": "report",
})
builder.add_edge("report", END)

graph = builder.compile()
