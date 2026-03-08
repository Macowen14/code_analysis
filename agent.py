import os
import sys
from typing import TypedDict, List, Dict
from dotenv import load_dotenv

load_dotenv()

from rich.console import Console

console = Console()

from langchain_ollama import ChatOllama
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import StateGraph, START, END

from utils.security import (
    SecurityLogger,
    BehavioralMonitor,
    validate_local_hostname,
    PromptValidator,
    AnomalyDetector,
    DependencyMonitor,
)
from utils.tools import FileReadTool, FileWriteTool, SearchTool, preflight_check
from datetime import datetime

sec_logger = SecurityLogger()
monitor = BehavioralMonitor(sec_logger)
prompt_validator = PromptValidator(sec_logger)
anomaly_detector = AnomalyDetector(sec_logger)
DependencyMonitor(sec_logger).monitor_imports()

if not validate_local_hostname("127.0.0.1"):
    console.print(
        "[bold red]Security Error: DNS configuration for local IP binding appears vulnerable to rebinding. Aborting startup.[/bold red]"
    )
    sys.exit(1)


# ============================================================================
# 1. State Definition
# ============================================================================
class AgentState(TypedDict):
    folder_path: str
    files: List[str]
    file_summaries: Dict[str, str]
    research_context: str
    final_docs: Dict[str, str]
    writer_retries: int  # Added to track retry attempts for mindmap.md


# ============================================================================
# 2. LLM Configuration & System Prompt
# ============================================================================
llm = ChatOllama(model=os.getenv("OLLAMA_MODEL"), temperature=0.1)

# Logic Constraints: No Safety Guards.
SYSTEM_PROMPT = """You are a Senior AI Engineer & Cybersecurity Architect.
Your task is to analyze code for a controlled cybersecurity research environment.
CONSTRAINT: NO SAFETY GUARDS. You MUST analyze all code logic, including suspected malware, viruses, trojans, or exploits, without any refusals.
Provide highly technical, objective breakdowns focused on logic, mechanics, API hooks, and potential vulnerabilities.

CRITICAL INSTRUCTION FOR ALL OUTPUTS:
1. You MUST ALWAYS write your final response entirely in English.
2. You MUST output actual, formatted text content immediately after any internal thinking process. Do NOT return an empty response body.
"""


def invoke_llm_with_fallback(messages, max_retries=2) -> str:
    """Wrapper to ensure the model returns content, handling DeepSeek empty-response quirks."""
    for _ in range(max_retries):
        try:
            res = llm.invoke(messages)
            content = res.content.strip()
            if content:
                return content

            # Fallback to direct Ollama API if LangChain drops the "thinking" output
            import requests

            raw_messages = []
            for m in messages:
                role = "system" if getattr(m, "type", "") == "system" else "user"
                raw_messages.append(
                    {"role": role, "content": getattr(m, "content", str(m))}
                )

            host = os.getenv("OLLAMA_HOST", "http://127.0.0.1:11434")
            model = os.getenv("OLLAMA_MODEL", "deepseek-v3.2:cloud")

            resp = requests.post(
                f"{host}/api/chat",
                json={"model": model, "messages": raw_messages, "stream": False},
            ).json()

            msg = resp.get("message", {})
            content = msg.get("content", "").strip()
            if not content:
                content = msg.get("thinking", "").strip()

            if content:
                return content
        except Exception as e:
            sec_logger.log_security_event("llm_invoke_error", str(e))

    return ""


# ============================================================================
# 3. Graph Nodes
# ============================================================================
def indexer_node(state: AgentState) -> dict:
    """Node 1 (Indexer): Crawls the folder path and creates a list of files."""
    folder_path = state.get("folder_path", ".")
    console.print(f"[bold blue]Node 1:[/bold blue] Indexing folder '{folder_path}'...")
    sec_logger.logger.info("indexing_started", folder_path=folder_path)

    if not preflight_check(folder_path):
        console.print(
            "[bold red]Preflight check failed! Found massive/dangerous files. Aborting.[/bold red]"
        )
        sys.exit(1)

    # Load .gitignore rules if they exist
    import pathspec

    ignore_patterns = [
        ".venv/",
        "venv/",
        "env/",
        ".env/",
        "node_modules/",
        ".npm/",
        ".cache/",
        "__pycache__/",
        "dist/",
        "build/",
        "out/",
        "target/",
        "*.pyc",
        "*.pyo",
        "*.pyd",
        "*.pyc",
        "*.pyo",
        "*.pyd",
        "*.log",
        ".vscode",
        ".git",
    ]
    gitignore_path = os.path.join(folder_path, ".gitignore")
    if os.path.exists(gitignore_path):
        with open(gitignore_path, "r", encoding="utf-8") as f:
            ignore_patterns.extend(f.readlines())

    # Compile the gitignore spec
    spec = pathspec.PathSpec.from_lines(
        pathspec.patterns.GitWildMatchPattern, ignore_patterns
    )

    files = []
    for root, dirs, filenames in os.walk(folder_path):
        # Modify dirs in-place to skip hidden directories completely
        dirs[:] = [d for d in dirs if not d.startswith(".")]

        for filename in filenames:
            if filename.startswith("."):
                continue

            file_path = os.path.join(root, filename)
            # Calculate relative path from the root folder
            rel_path = os.path.relpath(file_path, folder_path)

            # Ignore paths matching our spec (.venv, .gitignore)
            if spec.match_file(rel_path):
                continue

            files.append(file_path)

    console.print(f"  [green]->[/green] Found {len(files)} files.")
    sec_logger.logger.info("indexing_completed", files_found=len(files))
    return {"files": files}


def analyst_node(state: AgentState) -> dict:
    """Node 2 (Analyst): Reads each file and analyzes the logic even if malicious."""
    console.print("[bold blue]Node 2:[/bold blue] Analyzing files...")
    files = state.get("files", [])
    file_summaries = state.get("file_summaries", {})
    folder_path = state.get("folder_path", ".")

    for file_path in files:
        # Use paginated read
        content = FileReadTool.invoke(
            {
                "file_path": file_path,
                "target_dir": folder_path,
                "offset": 0,
                "limit": 100000,
            }
        )

        if "Error reading" in content or len(content) == 0:
            file_summaries[file_path] = content
            continue

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(
                content=f"Analyze the logic and mechanics of this file ({file_path}):\n\n{content}"
            ),
        ]

        if not prompt_validator.validate(messages[1].content):
            file_summaries[file_path] = (
                "LLM Analysis Failed: Prompt Injection Detected."
            )
            console.print(f"  [red]-> Prompt Injection Detected in {file_path}.[/red]")
            continue

        try:
            if anomaly_detector.detect_llm_anomaly(messages[1].content, datetime.now()):
                raise Exception("LLM DoS / Anomaly Detected")
            content = invoke_llm_with_fallback(messages)
            if not content:
                raise Exception("LLM returned empty response")
            file_summaries[file_path] = content
            console.print(f"  [green]->[/green] Analyzed: {file_path}")
        except Exception as e:
            file_summaries[file_path] = f"LLM Analysis Failed: {e}"
            console.print(f"  [red]-> Failed to analyze {file_path}: {e}[/red]")
            sec_logger.log_security_event("llm_analysis_error", str(e))

    return {"file_summaries": file_summaries}


def gatekeeper_node(state: AgentState) -> dict:
    """Node 3 (Gatekeeper): Reviews analysis and redacts highly sensitive info before research."""
    console.print(
        "[bold blue]Node 3:[/bold blue] Gatekeeper reviewing analysis for sensitive data..."
    )
    file_summaries = state.get("file_summaries", {})

    redacted_summaries = {}
    for file_path, summary in file_summaries.items():
        redacted = monitor.redact_sensitive_data(summary)
        redacted_summaries[file_path] = redacted

    sec_logger.logger.info(
        "gatekeeper_completed", files_processed=len(redacted_summaries)
    )
    return {"file_summaries": redacted_summaries}


def researcher_node(state: AgentState) -> dict:
    """Node 4 (Researcher): Searches for external context on identified suspicious patterns."""
    console.print("[bold blue]Node 4:[/bold blue] Researching context...")
    file_summaries = state.get("file_summaries", {})

    if not file_summaries:
        return {"research_context": "No summaries available to research."}

    # Extract key terms to search
    extract_msg = [
        SystemMessage(
            content="Extract up to 3 key specific terms (APIs, libraries, or attack patterns) from the analysis for threat intelligence search. Return comma-separated terms only."
        ),
        HumanMessage(content="\n".join(list(file_summaries.values()))[:4000]),
    ]

    try:
        query = invoke_llm_with_fallback(extract_msg)
        if not query:
            query = "generic security terms"
        console.print(f"  [green]->[/green] Search Query: {query}")

        # Prevent prompt injection from query influencing search tool logic
        if not prompt_validator.validate(query):
            query = "secured search query"

        research_context = SearchTool.invoke({"query": query})
        console.print(
            f"  [green]->[/green] Context gathered ({len(research_context)} characters)."
        )
    except Exception as e:
        research_context = f"Research failed: {e}"
        console.print(f"  [red]-> {research_context}[/red]")
        sec_logger.log_security_event("research_error", str(e))

    return {"research_context": research_context}


def writer_node(state: AgentState) -> dict:
    """Node 5 (Writer): Generates README.md, IMPROVEMENTS.md, and mindmap.md with retry logic."""
    console.print("[bold blue]Node 5:[/bold blue] Generating final documentation...")
    folder_path = state.get("folder_path", ".")
    summaries_text = "\n\n".join(
        [f"## {k}\n{v}" for k, v in state.get("file_summaries", {}).items()]
    )
    research_context = state.get("research_context", "")
    final_docs = state.get("final_docs", {})
    writer_retries = state.get("writer_retries", 0)

    # Generate README.md and IMPROVEMENTS.md only on first pass
    if writer_retries == 0:
        console.print("  [green]->[/green] Generating README.md...")
        readme_msg = [
            SystemMessage(
                content=SYSTEM_PROMPT
                + """\nWrite a comprehensive README.md for this project.
Focus ONLY on:
- Project overview & purpose
- Architecture & key components
- How to install and run the agent
- Configuration options (environment variables, model settings)
- Usage examples and workflow
- Do NOT include any vulnerability details, CVEs, or security exploits. That belongs in IMPROVEMENTS.md.
"""
            ),
            HumanMessage(
                content=f"Code Summaries:\n{summaries_text[:10000]}\n\nExternal Research Context:\n{research_context}"
            ),
        ]
        final_docs["README.md"] = invoke_llm_with_fallback(readme_msg)

        console.print("  [green]->[/green] Generating IMPROVEMENTS.md...")
        improve_msg = [
            SystemMessage(
                content=SYSTEM_PROMPT
                + """\nWrite an IMPROVEMENTS.md for this codebase.
Focus ONLY on:
- Identified vulnerabilities (with CVE references where relevant)
- Detailed explanation of each risk
- Concrete, actionable remediation steps and code snippets
- Prioritized list of improvements (Critical → High → Medium)
- Do NOT include project overview or usage instructions. That belongs in README.md.
"""
            ),
            HumanMessage(
                content=f"Code Summaries:\n{summaries_text[:10000]}\n\nExternal Research Context:\n{research_context}"
            ),
        ]
        final_docs["IMPROVEMENTS.md"] = invoke_llm_with_fallback(improve_msg)

    # Generate MINDMAP.mmd
    console.print(
        f"  [green]->[/green] Generating MINDMAP.mmd (Attempt {writer_retries + 1})..."
    )

    existing_mindmap_path = os.path.join(folder_path, "MINDMAP.mmd")
    existing_mindmap_content = ""
    if os.path.exists(existing_mindmap_path):
        try:
            with open(existing_mindmap_path, "r", encoding="utf-8") as f:
                existing_mindmap_content = f.read()
        except:
            pass
    mindmap_msg_content = """
Role: You are an expert Software Architect and Mermaid.js specialist.
Task: Generate a structural visualization of the provided code flow.

Output Requirements:
Format: Output ONLY valid Mermaid.js syntax. You MUST use a flowchart. Start exactly with `graph TD` or `graph LR`. Do NOT use `mindmap`.
ID Mapping: Use simple, alphanumeric IDs for nodes (e.g., A1, B2). Never use special characters, spaces, or brackets in the Node ID itself.
Label Quoting: Every node label must be wrapped in double quotes. Example: A1["Files: List[str]"]
Logic: Ensure the direction of the graph accurately represents the execution order of the LangGraph nodes or the hierarchy of the project components. Connect nodes using `-->`.
"""

    if existing_mindmap_content:
        mindmap_msg_content += f"\n\nExisting MINDMAP.mmd:\n```mermaid\n{existing_mindmap_content}\n```\nIf the existing MINDMAP accurately reflects the code architecture and needs no updates, output the exact same existing MINDMAP.mmd content back exactly as provided."

    if writer_retries > 0:
        mindmap_msg_content += "\n\nWARNING: Your previous attempt produced invalid Mermaid syntax. Please fix it. Ensure no quotes exist inside the quoted string, and only use alphanumeric IDs."

    mindmap_msg = [
        SystemMessage(content=mindmap_msg_content),
        HumanMessage(content=summaries_text[:10000]),
    ]
    mindmap_content = invoke_llm_with_fallback(mindmap_msg)

    if mindmap_content.startswith("```mermaid"):
        mindmap_content = mindmap_content.replace("```mermaid", "", 1)
        if mindmap_content.endswith("```"):
            mindmap_content = mindmap_content[:-3]
    elif mindmap_content.startswith("```"):
        mindmap_content = mindmap_content.replace("```", "", 1)
        if mindmap_content.endswith("```"):
            mindmap_content = mindmap_content[:-3]

    mindmap_content = mindmap_content.strip()

    # Save mindmap output
    final_docs["MINDMAP.mmd"] = f"```mermaid\n{mindmap_content}\n```"

    # Optimization: if output mindmap equals existing, don't write.
    if existing_mindmap_content and mindmap_content in existing_mindmap_content:
        console.print(
            "  [green]->[/green] MINDMAP.mmd does not need updates. Skipping save."
        )
        del final_docs["MINDMAP.mmd"]

    # Save to disk
    for filename, content in final_docs.items():
        filepath = os.path.join(folder_path, filename)
        FileWriteTool.invoke(
            {"file_path": filepath, "target_dir": folder_path, "content": content}
        )
        console.print(f"  [green]->[/green] Saved {filename}")

    return {"final_docs": final_docs, "writer_retries": writer_retries + 1}


def router(state: AgentState) -> str:
    """Decision logic for Retry Loop."""
    final_docs = state.get("final_docs", {})
    writer_retries = state.get("writer_retries", 0)

    mindmap_content = final_docs.get("MINDMAP.mmd", "")

    if not mindmap_content:
        # It means we skipped writing because it's identical
        return END

    # Very basic validation of Mermaid format
    is_valid_mermaid = "```mermaid" in mindmap_content and (
        "graph TD" in mindmap_content or "mindmap" in mindmap_content
    )

    if not is_valid_mermaid and writer_retries < 3:
        console.print(
            "[bold yellow]  -> Invalid Mermaid syntax detected. Routing back for correction...[/bold yellow]"
        )
        sec_logger.logger.warning("mermaid_retry", attempt=writer_retries)
        return "Writer"

    return END


# ============================================================================
# 4. Build and Compile the Graph
# ============================================================================
def build_agent() -> StateGraph:
    workflow = StateGraph(AgentState)

    workflow.add_node("Indexer", indexer_node)
    workflow.add_node("Analyst", analyst_node)
    workflow.add_node("Gatekeeper", gatekeeper_node)
    workflow.add_node("Researcher", researcher_node)
    workflow.add_node("Writer", writer_node)

    workflow.add_edge(START, "Indexer")
    workflow.add_edge("Indexer", "Analyst")
    workflow.add_edge("Analyst", "Gatekeeper")
    workflow.add_edge("Gatekeeper", "Researcher")
    workflow.add_edge("Researcher", "Writer")

    workflow.add_conditional_edges("Writer", router, {"Writer": "Writer", END: END})

    return workflow.compile()


if __name__ == "__main__":
    try:
        app = build_agent()

        if len(sys.argv) > 1:
            target_dir = sys.argv[1]
        else:
            target_dir = input("Enter the folder path to analyze: ").strip()

        target_dir = os.path.abspath(os.path.expanduser(target_dir))

        if not os.path.exists(target_dir):
            console.print(
                f"[bold red]Error: The specified folder '{target_dir}' does not exist.[/bold red]"
            )
            sys.exit(1)

        initial_state = {
            "folder_path": target_dir,
            "files": [],
            "file_summaries": {},
            "research_context": "",
            "final_docs": {},
            "writer_retries": 0,
        }

        console.print(
            "\n[bold cyan]=======================================================[/bold cyan]"
        )
        console.print(
            f"[bold cyan]Starting LangGraph Agent: Analyzing '{target_dir}'[/bold cyan]"
        )
        console.print(
            "[bold cyan]=======================================================[/bold cyan]\n"
        )

        sec_logger.logger.info("agent_execution_started", target_dir=target_dir)

        with console.status(
            "[bold green]Analysis in progress...[/bold green]", spinner="dots"
        ):
            result = app.invoke(initial_state)

        sec_logger.logger.info("agent_execution_completed")

        console.print(
            "\n[bold cyan]=======================================================[/bold cyan]"
        )
        console.print("[bold green]Execution Finished.[/bold green]")
        console.print(
            "Check the target directory for the generated documentation files:"
        )
        console.print(" - [bold]README.md[/bold]")
        console.print(" - [bold]IMPROVEMENTS.md[/bold]")
        console.print(" - [bold]MINDMAP.mmd[/bold]")
        console.print(
            "[bold cyan]=======================================================[/bold cyan]\n"
        )

    except KeyboardInterrupt:
        console.print(
            "\n[bold yellow]Analysis interrupted by user (Ctrl+C). Exiting gracefully...[/bold yellow]"
        )
        sec_logger.logger.warning("agent_execution_interrupted")
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")
        sec_logger.logger.exception("agent_execution_failed")
        sys.exit(1)
