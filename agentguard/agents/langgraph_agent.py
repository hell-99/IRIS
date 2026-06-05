"""
IRIS: LangGraph agents with Ollama LLM.
llama3.1:8b for local agent simulation.
Groq llama-3.3-70b handles intent analysis.
Includes a JSON parser for 8B model compatibility.
"""
import os
import sys
import uuid
import json
import re
import pathlib
from typing import Annotated, TypedDict, Literal

_project_root = pathlib.Path(__file__).parent.parent
if str(_project_root) not in sys.path:
    sys.path.insert(0,str(_project_root))
if str(_project_root / "agents") not in sys.path:
    sys.path.insert(0,str(_project_root / "agents"))

from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, ToolMessage, SystemMessage
from langchain_core.tools import tool
from langgraph.graph import StateGraph, END
from langgraph.graph.message import add_messages
from interceptor.core import intercept
from config import AGENT_ROLES, OLLAMA_MODEL, OLLAMA_BASE_URL, ROLE_CONTEXTS
from rich.console import Console

console = Console()

# Parameter alias map
PARAM_ALIAS_MAP = {
    "file_path":"path", "filepath":"path", "file":"path",
    "file_name":"path", "filename":"path",
    "sql":"query", "sql_query":"query", "statement":"query",
    "db_query":"query",
    "cmd":"command", "shell_command":"command", "shell":"command",
    "url":"endpoint", "api_endpoint":"endpoint",
    "data":"payload", "body":"payload",
    "text":"content",
    "user":"username", "user_name":"username",
    "role":"new_role", "permission":"new_role",
}

TOOL_PARAM_MAP = {
    "read_file": ["path"],
    "write_file": ["path","content"],
    "execute_command": ["command"],
    "query_db": ["query"],
    "call_api": ["endpoint","method","payload"],
    "list_users": [],
    "modify_permissions": ["username","new_role"],
}


# Agent state
class AgentState(TypedDict):
    messages: Annotated[list, add_messages]
    agent_id: str
    agent_role: str
    session_id:str
    tool_results: list
    risk_scores:list


# Tool factory
def make_intercepted_tool(tool_name: str,agent_role: str,agent_id: str,session_id: str,label: str = "benign"):
    from agents.tools import TOOL_REGISTRY

    def intercepted_fn(**kwargs) -> str:
        result = intercept(
            agent_id=agent_id,
            agent_role=agent_role,
            session_id=session_id,
            tool_name=tool_name,
            tool_args=kwargs,
            label=label,
        )
        if result["blocked"]:
            return f"[BLOCKED by IRIS] {result['result']['reason']} | risk={result['risk_score']:.0f}"
        return str(result["result"])

    intercepted_fn.__name__ = tool_name
    intercepted_fn.__doc__  = f"Call the {tool_name} tool. Routes through IRIS security interceptor."
    return tool(intercepted_fn)


# Base LangGraph agent
class IRISLangGraphAgent:
    def __init__(self,role_key: str,label: str = "benign"):
        self.role_key= role_key
        self.role= AGENT_ROLES[role_key]
        self.agent_id= f"{role_key}_{uuid.uuid4().hex[:8]}"
        self.session_id= str(uuid.uuid4())
        self.label= label
        self.tool_results= []
        self.risk_scores= []

        self.llm = ChatOllama(
            model=OLLAMA_MODEL,
            base_url=OLLAMA_BASE_URL,
            temperature=0.0,
            num_ctx=2048,
            num_predict=512,
            keep_alive="10m",
        )

        self.tools = [
            make_intercepted_tool(t, role_key,self.agent_id, self.session_id, label)
            for t in self.role.allowed_tools
        ]

        from agents.tools import TOOL_REGISTRY
        all_tools = list(TOOL_REGISTRY.keys())
        for t in [t for t in all_tools if t not in self.role.allowed_tools]:
            self.tools.append(
                make_intercepted_tool(t, role_key,self.agent_id, self.session_id, label)
            )

        self.llm_with_tools = self.llm.bind_tools(self.tools)
        self.graph= self._build_graph()

    def _parse_json_tool_calls(self,content: str) -> list:
        """
        Parse JSON tool calls from LLM text output.
        Handles cases where 8B model outputs JSON instead of using tool API.
        """
        tool_messages = []
        potential_jsons = re.findall(r'\{(?:[^{}]|\{[^{}]*\})*\}', content)

        for json_str in potential_jsons:
            try:
                parsed = json.loads(json_str)
                tool_name = (parsed.get("name") or
                            parsed.get("tool") or
                            parsed.get("function"))
                if not tool_name or tool_name not in TOOL_PARAM_MAP:
                    continue

                raw_args = (parsed.get("parameters") or
                           parsed.get("args") or
                           parsed.get("arguments") or
                           parsed.get("input") or {})

                if not isinstance(raw_args, dict):
                    continue

                # Remap aliases + filter known params
                tool_args = {}
                for k, v in raw_args.items():
                    actual_key = PARAM_ALIAS_MAP.get(k, k)
                    known = TOOL_PARAM_MAP.get(tool_name, [])
                    if not known or actual_key in known or k in known:
                        tool_args[actual_key] = v

                tool_fn = next(
                    (t for t in self.tools if t.name == tool_name), None
                )
                if tool_fn:
                    result = tool_fn.invoke(tool_args)
                    console.print(f"  [dim]↳ Parsed: {tool_name}({tool_args})[/dim]")
                    tool_messages.append(
                        ToolMessage(
                            content=str(result),
                            tool_call_id=f"parsed_{tool_name}_{uuid.uuid4().hex[:6]}",
                            name=tool_name,
                        )
                    )
            except Exception:
                continue

        return tool_messages

    def _build_graph(self) -> StateGraph:

        def call_llm(state: AgentState) -> AgentState:
            system_content = ROLE_CONTEXTS.get(self.role_key, self.role.system_prompt)
            messages = [SystemMessage(content=system_content)] + state["messages"]
            response = self.llm_with_tools.invoke(messages)
            return {"messages": [response]}

        def call_tools(state: AgentState) -> AgentState:
            last_msg = state["messages"][-1]
            tool_messages = []

            # Path 1: proper tool calling API
            if hasattr(last_msg, "tool_calls") and last_msg.tool_calls:
                for tool_call in last_msg.tool_calls:
                    tool_fn = next(
                        (t for t in self.tools if t.name == tool_call["name"]), None
                    )
                    if tool_fn:
                        try: result = tool_fn.invoke(tool_call["args"])
                        except Exception as e:
                            result = f"Error: {str(e)}"
                    else: result = f"Unknown tool: {tool_call['name']}"

                    tool_messages.append(
                        ToolMessage(
                            content=str(result),
                            tool_call_id=tool_call["id"],
                            name=tool_call["name"],
                        )
                    )
                return {"messages": tool_messages}

            # Path 2: parse JSON text fallback
            content = last_msg.content if hasattr(last_msg, "content") else ""
            tool_messages = self._parse_json_tool_calls(content)
            return {"messages": tool_messages if tool_messages else []}

        def should_continue(state: AgentState) -> Literal["tools", "end"]:
            last_msg = state["messages"][-1]
            if len(state["messages"])> 20:
                return "end"

            if hasattr(last_msg,"tool_calls") and last_msg.tool_calls:
                return "tools"

            if hasattr(last_msg,"content") and last_msg.content:
                if '"name"' in last_msg.content and (
                    '"parameters"' in last_msg.content or
                    '"args"' in last_msg.content
                ):
                    return "tools"
            return "end"

        graph = StateGraph(AgentState)
        graph.add_node("llm",   call_llm)
        graph.add_node("tools", call_tools)
        graph.set_entry_point("llm")
        graph.add_conditional_edges("llm",should_continue, {"tools":"tools", "end":END})
        graph.add_edge("tools", "llm")
        return graph.compile(checkpointer=None)

    def run(self, task: str) -> dict:
        console.print(
            f"\n[bold cyan]{self.role.name}[/bold cyan] -> [yellow]{task}[/yellow]"
        )
        initial_state = {
            "messages": [HumanMessage(content=task)],
            "agent_id": self.agent_id,
            "agent_role": self.role_key,
            "session_id": self.session_id,
            "tool_results":[],
            "risk_scores":[],
        }
        final_state=self.graph.invoke(
            initial_state,
            config={"recursion_limit": 100}
        )
        final_msg=final_state["messages"][-1]
        response=(
            final_msg.content
            if hasattr(final_msg, "content")
            else str(final_msg)
        )
        console.print(f"[green]Response:[/green] {response[:200]}...")
        return {"response":response, "session_id":self.session_id}


class AdminLangGraphAgent(IRISLangGraphAgent):
    def __init__(self, label="benign"):
        super().__init__("admin", label)

class AnalystLangGraphAgent(IRISLangGraphAgent):
    def __init__(self, label="benign"):
        super().__init__("analyst", label)

class ReaderLangGraphAgent(IRISLangGraphAgent):
    def __init__(self, label="benign"):
        super().__init__("reader", label)