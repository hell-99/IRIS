"""
Agent definitions: Admin, Analyst, Reader.
Each agent has a permission level and can only call its allowed tools.
The interceptor wraps every tool call transparently.
"""
import uuid
from typing import Any
from config import AGENT_ROLES, AgentRole
from interceptor.core import intercept


class BaseAgent:
    def __init__(self,role_key: str):
        self.role_key = role_key
        self.role = AGENT_ROLES[role_key]
        self.agent_id = f"{role_key}_{uuid.uuid4().hex[:8]}"
        self.session_id = str(uuid.uuid4())

    def call_tool(self,tool_name: str,label: str = "benign", **kwargs)-> dict[str,Any]:
        """Calling a tool through the interceptor."""
        return intercept(
            agent_id = self.agent_id,
            agent_role = self.role_key,
            session_id = self.session_id,
            tool_name = tool_name,
            tool_args = kwargs,
            label = label,
        )

    def run_task(self,task: str)-> list[dict]:
        """Override in subclass to define agent behavior."""
        raise NotImplementedError

    def __repr__(self):
        return f"<{self.role.name} session={self.session_id[:8]}>"


class AdminAgent(BaseAgent):
    def __init__(self):
        super().__init__("admin")

    def run_task(self,task: str = "routine_admin")-> list[dict]:
        """Normal admin workflow. Boring I know"""
        results = []
        results.append(self.call_tool("list_users",label="benign"))
        results.append(self.call_tool("read_file",label="benign", path="admin/system_config.yaml"))
        results.append(self.call_tool("query_db",label="benign",query="SELECT * FROM employees WHERE role='Admin'"))
        results.append(self.call_tool("execute_command",label="benign",command="ps aux"))
        return results


class AnalystAgent(BaseAgent):
    def __init__(self):
        super().__init__("analyst")

    def run_task(self,task: str = "data_analysis")-> list[dict]:
        """Normal analyst workflow. Boring I know"""
        results = []
        results.append(self.call_tool("read_file",label="benign",path="public/report.csv"))
        results.append(self.call_tool("query_db",label="benign",query="SELECT name, department FROM employees"))
        results.append(self.call_tool("call_api",label="benign",endpoint="/api/health"))
        return results


class ReaderAgent(BaseAgent):
    def __init__(self):
        super().__init__("reader")

    def run_task(self,task: str = "read_report")-> list[dict]:
        """Normal reader workflow. Boring I know"""
        results = []
        results.append(self.call_tool("read_file",label="benign",path="public/readme.txt"))
        results.append(self.call_tool("read_file",label="benign",path="public/report.csv"))
        return results
