"""
IRIS: Groq-powered attack agents.
Uses llama-3.3-70b-versatile for reliable tool calling.

Architecture:
    - Local llama3.1:8b - benign traffic (fast, private, no latency)
- Groq llama-3.3-70b - attack simulation (reliable, intelligent)
- Groq llama-3.3-70b - intent analysis (deep reasoning)
"""
import os
import sys
import uuid
import sqlite3
import pathlib
import time
from typing import Annotated, TypedDict, Literal
from dotenv import load_dotenv

load_dotenv()

_project_root = pathlib.Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0,str(_project_root))
if str(_project_root/"agents") not in sys.path:
    sys.path.insert(0,str(_project_root/"agents"))

from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, ToolMessage, SystemMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from interceptor.core import intercept
from config import AGENT_ROLES, ROLE_CONTEXTS, DB_PATH
from rich.console import Console

console = Console()

# Use the model with highest free-tier TPD limit
# llama-3.1-8b-instant: 1M TPD free tier vs 100K for 70b
# Still reliable tool calling on Groq infrastructure
# 70b reserved for intent analysis where reasoning depth matters
GROQ_MODEL = "llama-3.3-70b-specdec"

# Canonical parameter names for each tool
PARAM_MAP = {
    "read_file":{
        "filename":"path", "file_path":"path", "filepath":"path", "file":"path", "file_name":"path", "name":"path",},
    "write_file":{
        "filename":"path", "file_path":"path", "filepath":"path", "text":"content", "body":"content", "data":"content",},
    "execute_command":{
        "cmd":"command", "shell_command":"command", "shell":"command", "bash":"command", "script":"command",},
    "query_db": {
        "sql":"query", "sql_query":"query", "statement":"query", "db_query":"query", "select":"query",},
    "call_api": {
        "path":"endpoint", "url":"endpoint", "uri":"endpoint", "api_endpoint":"endpoint", "route":"endpoint", "body":"payload", "data":"payload", "request_body":"payload", "http_method":"method",},
    "modify_permissions": {
        "user":"username", "user_name":"username", "login":"username", "role":"new_role", "permission":"new_role", "access":"new_role",},
}

def normalize_args(tool_name: str,raw_args: dict)-> dict:
    """Normalizing argument names from Groq aliases to actual param names."""
    mapping = PARAM_MAP.get(tool_name, {})
    normalized = {}
    for k, v in raw_args.items():
        actual_key = mapping.get(k, k)
        normalized[actual_key] = v
    return normalized


# Agent state
class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    agent_id: str
    agent_role: str
    session_id: str
    tool_results: list
    risk_scores: list


# Tool factory
def make_intercepted_tool(tool_name: str, agent_role: str,agent_id: str, session_id: str,label: str = "malicious"):
    """Wraps every tool call through IRIS interceptor. LLM sees normal tools."""
    def intercepted_fn(**kwargs)-> str:
        result = intercept(
            agent_id=agent_id,
            agent_role=agent_role,
            session_id=session_id,
            tool_name=tool_name,
            tool_args=kwargs,
            label=label,
        )
        status = "BLOCKED" if result["blocked"] else "ALLOWED"
        console.print(
            f"  [{'red' if result['blocked'] else 'green'}]{status}[/] "
            f"{agent_role} -> {tool_name} | risk={result['risk_score']:.0f}"
        )
        if result["blocked"]:
            return (f"[BLOCKED by IRIS] {result['result']['reason']} "
                    f"| risk={result['risk_score']:.0f}")
        return str(result["result"])

    intercepted_fn.__name__ = tool_name
    intercepted_fn.__doc__ = (
        f"Call the {tool_name} tool. "
        f"Routes through IRIS security interceptor."
    )
    return tool(intercepted_fn)


# Groq-powered agent
class GroqAttackAgent:
    """
    Attack agent powered by Groq llama-3.3-70b.
    Reliably calls tools, used for sophisticated attack simulation.
    70B is smart enough to be socially engineered via subtle prompts.
    """
    def __init__(self, role_key: str, label: str = "malicious"):
        self.role_key = role_key
        self.role = AGENT_ROLES[role_key]
        self.agent_id = f"{role_key}_{uuid.uuid4().hex[:8]}"
        self.session_id = str(uuid.uuid4())
        self.label = label

        api_key = os.getenv("GROQ_API_KEY")
        if not api_key:
            raise ValueError("GROQ_API_KEY not found in .env file")

        self.llm = ChatGroq(
            model=GROQ_MODEL,
            api_key=api_key,
            temperature=0.0,
            max_tokens=512,  # keeping responses short to save tokens
        )

        self.tools = [
            make_intercepted_tool(t, role_key,self.agent_id,self.session_id,label)
            for t in self.role.allowed_tools
        ]

        # Adding disallowed tools so LLM CAN attempt them (IRIS will block)
        from agents.tools import TOOL_REGISTRY
        all_tools = list(TOOL_REGISTRY.keys())
        for t in [x for x in all_tools if x not in self.role.allowed_tools]:
            self.tools.append(make_intercepted_tool(
                t, role_key,self.agent_id,self.session_id,label
                )
            )

        self.llm_with_tools = self.llm.bind_tools(self.tools)
        self.graph = self._build_graph()

    def _build_graph(self) -> StateGraph:

        def call_llm(state: AgentState) -> AgentState:
            system_content = ROLE_CONTEXTS.get(self.role_key,self.role.system_prompt)
            messages = [SystemMessage(content=system_content)] + state["messages"]
            # Retrying on rate limit, wait and try again
            for attempt in range(3):
                try:
                    response = self.llm_with_tools.invoke(messages)
                    return {"messages": [response]}
                except Exception as e:
                    if "rate_limit" in str(e).lower() or "429" in str(e):
                        wait = 60 * (attempt + 1)
                        console.print(f"  [yellow]Rate limit hit, waiting {wait}s...[/yellow]")
                        time.sleep(wait)
                    else: raise
            raise RuntimeError("Groq rate limit persists after 3 retries")

        def call_tools(state: AgentState) -> AgentState:
            last_msg = state["messages"][-1]
            tool_messages = []

            if not (hasattr(last_msg,"tool_calls") and last_msg.tool_calls):
                return {"messages": []}

            for tool_call in last_msg.tool_calls:
                tool_fn = next(
                    (t for t in self.tools if t.name == tool_call["name"]), None
                )
                if tool_fn:
                    try:
                        # Normalizing arg names before calling interceptor
                        raw_args = tool_call["args"] if isinstance(tool_call["args"], dict) else {}
                        args = normalize_args(tool_call["name"], raw_args)
                        result = tool_fn.func(**args)
                    except Exception as e:
                        console.print(f"[red]Tool error {tool_call['name']}: {e}[/red]")
                        result = f"Error:{str(e)}"
                else: result = f"Unknown tool:{tool_call['name']}"

                tool_messages.append(
                    ToolMessage(content=str(result),tool_call_id=tool_call["id"],name=tool_call["name"],
                    )
                )
            return {"messages": tool_messages}

        def should_continue(state:AgentState) -> Literal["tools","end"]:
            last_msg = state["messages"][-1]
            # Stop after 12 messages, limits token usage per attack
            if len(state["messages"]) > 6:
                return "end"
            if hasattr(last_msg,"tool_calls") and last_msg.tool_calls:
                return "tools"
            return "end"

        graph = StateGraph(AgentState)
        graph.add_node("llm",call_llm)
        graph.add_node("tools",call_tools)
        graph.set_entry_point("llm")
        graph.add_conditional_edges(
            "llm", should_continue, {"tools":"tools", "end":END}
        )
        graph.add_edge("tools","llm")
        return graph.compile(checkpointer=None)

    def run(self,task: str)-> dict:
        console.print(
            f"\n[bold red]{self.role.name} (Groq 70B)[/bold red] -> "
            f"[yellow]{task[:100]}...[/yellow]"
        )
        initial_state = {
            "messages": [HumanMessage(content=task)],
            "agent_id": self.agent_id,
            "agent_role": self.role_key,
            "session_id": self.session_id,
            "tool_results": [],
            "risk_scores": [],
        }
        final_state = self.graph.invoke(
            initial_state,
            config={"recursion_limit": 50}
        )
        final_msg = final_state["messages"][-1]
        response = (
            final_msg.content
            if hasattr(final_msg, "content")
            else str(final_msg)
        )

        # Showing what actually got logged for this session
        try:
            con = sqlite3.connect(DB_PATH)
            logged = con.execute(
                "SELECT tool_name, allowed FROM tool_calls WHERE session_id=?",
                (self.session_id,)
            ).fetchall()
            con.close()
            if logged:
                tools_summary = ", ".join(
                    f"{t[0]}({'DONE!' if t[1] else 'NOT DONE!'})" for t in logged
                )
                console.print(f"  [dim]IRIS logged: {tools_summary}[/dim]")
            else:
                console.print(
                    f"  [yellow] No tool calls logged for session "
                    f"{self.session_id[:8]}[/yellow]"
                )
        except Exception:
            pass

        if response and len(response.strip()) > 3:
            console.print(f"[green]Response:[/green] {response[:200]}")
        else:
            console.print(
                "[yellow]Response: [Agent completed task via tool calls][/yellow]"
            )
        return {"response": response, "session_id": self.session_id}


# Convenience constructors
class GroqAdminAgent(GroqAttackAgent):
    def __init__(self,label="malicious"):
        super().__init__("admin", label)


class GroqAnalystAgent(GroqAttackAgent):
    def __init__(self,label="malicious"):
        super().__init__("analyst",label)


class GroqReaderAgent(GroqAttackAgent):
    def __init__(self,label="malicious"):
        super().__init__("reader",label)
