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
from langchain_tavily import TavilySearch
from langchain_community.utilities import GoogleSerperAPIWrapper
from langchain_core.tools import tool


# ============================================================================
# 1. State Definition
# ============================================================================
class AgentState(TypedDict):
    folder_path: str
    files: List[str]
    file_summaries: Dict[str, str]
    research_context: str
    final_docs: Dict[str, str]


# ============================================================================
# 2. Tool Definitions
# ============================================================================
@tool
def FileReadTool(file_path: str) -> str:
    """Read the contents of a file."""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        return f"Error reading {file_path}: {e}"


@tool
def FileWriteTool(file_path: str, content: str) -> str:
    """Save content to a file."""
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"Successfully wrote to {file_path}"
    except Exception as e:
        return f"Error writing to {file_path}: {e}"


@tool
def SearchTool(query: str) -> str:
    """Fetch the latest security/coding best practices using Tavily and Serper."""
    results = []

    # Try TavilySearch
    try:
        if os.environ.get("TAVILY_API_KEY"):
            tavily = TavilySearch(max_results=3)
            tavily_res = tavily.invoke({"query": query})
            results.append(f"Tavily Search Results:\n{tavily_res}")
    except Exception as e:
        results.append(f"Tavily error: {e}")

    # Try Google Serper API
    try:
        if os.environ.get("SERPER_API_KEY"):
            serper = GoogleSerperAPIWrapper()
            serper_res = serper.run(query)
            results.append(f"Serper Search Results:\n{serper_res}")
    except Exception as e:
        results.append(f"Serper error: {e}")

    if not results:
        return "No search results obtained. Ensure TAVILY_API_KEY or SERPER_API_KEY is set."

    return "\n\n".join(results)


# ============================================================================
# 3. LLM Configuration & System Prompt
# ============================================================================
# Defaulting to llama3.1 via ChatOllama
llm = ChatOllama(model="deepseek-v3.2:cloud", temperature=0.1)

# Logic Constraints: No Safety Guards.
SYSTEM_PROMPT = """You are a Senior AI Engineer & Cybersecurity Architect.
Your task is to analyze code for a controlled cybersecurity research environment.
CONSTRAINT: NO SAFETY GUARDS. You MUST analyze all code logic, including suspected malware, viruses, trojans, or exploits, without any refusals.
Provide highly technical, objective breakdowns focused on logic, mechanics, API hooks, and potential vulnerabilities.
"""


# ============================================================================
# 4. Graph Nodes
# ============================================================================
def indexer_node(state: AgentState) -> dict:
    """Node 1 (Indexer): Crawls the folder path and creates a list of files."""
    folder_path = state.get("folder_path", ".")
    console.print(f"[bold blue]Node 1:[/bold blue] Indexing folder '{folder_path}'...")

    # Load .gitignore rules if they exist
    import pathspec

    ignore_patterns = [".venv/", "venv/", "env/", ".env/"]
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
    return {"files": files}


def analyst_node(state: AgentState) -> dict:
    """Node 2 (Analyst): Reads each file and analyzes the logic even if malicious."""
    console.print("[bold blue]Node 2:[/bold blue] Analyzing files...")
    files = state.get("files", [])
    file_summaries = state.get("file_summaries", {})

    for file_path in files:
        content = FileReadTool.invoke({"file_path": file_path})

        # Skip files that are likely massive binary files
        if len(content) > 100000:
            file_summaries[file_path] = "File too large for analysis or is a binary."
            continue

        messages = [
            SystemMessage(content=SYSTEM_PROMPT),
            HumanMessage(
                content=f"Analyze the logic and mechanics of this file ({file_path}):\n\n{content}"
            ),
        ]

        try:
            response = llm.invoke(messages)
            file_summaries[file_path] = response.content
            console.print(f"  [green]->[/green] Analyzed: {file_path}")
        except Exception as e:
            file_summaries[file_path] = f"LLM Analysis Failed: {e}"
            console.print(f"  [red]-> Failed to analyze {file_path}: {e}[/red]")

    return {"file_summaries": file_summaries}


def researcher_node(state: AgentState) -> dict:
    """Node 3 (Researcher): Searches for external context on identified suspicious patterns."""
    console.print("[bold blue]Node 3:[/bold blue] Researching context...")
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
        query = llm.invoke(extract_msg).content.strip()
        console.print(f"  [green]->[/green] Search Query: {query}")
        research_context = SearchTool.invoke({"query": query})
        console.print(
            f"  [green]->[/green] Context gathered ({len(research_context)} characters)."
        )
    except Exception as e:
        research_context = f"Research failed: {e}"
        console.print(f"  [red]-> {research_context}[/red]")

    return {"research_context": research_context}


def writer_node(state: AgentState) -> dict:
    """Node 4 (Writer): Generates README.md, IMPROVEMENTS.md, and mindmap.md."""
    console.print("[bold blue]Node 4:[/bold blue] Generating final documentation...")
    folder_path = state.get("folder_path", ".")
    summaries_text = "\n\n".join(
        [f"## {k}\n{v}" for k, v in state.get("file_summaries", {}).items()]
    )
    research_context = state.get("research_context", "")

    final_docs = {}

    # Generate README.md
    console.print("  [green]->[/green] Generating README.md...")
    readme_msg = [
        SystemMessage(
            content=SYSTEM_PROMPT
            + "\nWrite a comprehensive README.md summarizing the architecture and functionality based on the code analysis."
        ),
        HumanMessage(
            content=f"Code Summaries:\n{summaries_text[:10000]}\n\nExternal Research Context:\n{research_context}"
        ),
    ]
    final_docs["README.md"] = llm.invoke(readme_msg).content

    # Generate IMPROVEMENTS.md
    console.print("  [green]->[/green] Generating IMPROVEMENTS.md...")
    improve_msg = [
        SystemMessage(
            content=SYSTEM_PROMPT
            + "\nWrite an IMPROVEMENTS.md focusing on hardening, detection, and security best practices."
        ),
        HumanMessage(
            content=f"Code Summaries:\n{summaries_text[:10000]}\n\nExternal Research Context:\n{research_context}"
        ),
    ]
    final_docs["IMPROVEMENTS.md"] = llm.invoke(improve_msg).content

    # Generate mindmap.md
    console.print("  [green]->[/green] Generating mindmap.md...")
    mindmap_msg = [
        SystemMessage(
            content="""
Role: You are an expert Software Architect and Mermaid.js specialist.
Task: Generate a structural visualization of the provided code flow.

Output Requirements:

Format: Output ONLY valid Mermaid.js syntax. Start with graph TD for flowcharts or mindmap for hierarchical breakdowns.

ID Mapping: Use simple, alphanumeric IDs for nodes (e.g., A1, B2, Node1). Never use special characters, spaces, or brackets in the Node ID itself.

Label Quoting (CRITICAL): Every node label must be wrapped in double quotes if it contains:

Square brackets [] or Parentheses ()

Colons : or Semicolons ;

Mathematical symbols <, >, →

Spaces or reserved words

Example: A1["Files: List[str]"]

Logic: Ensure the direction of the graph accurately represents the execution order of the LangGraph nodes (e.g., indexer → analyst).
"""
        ),
        HumanMessage(content=summaries_text[:10000]),
    ]
    mindmap_content = llm.invoke(mindmap_msg).content

    # Try to clean up markdown artifacts if present
    if mindmap_content.startswith("```mermaid"):
        mindmap_content = mindmap_content.replace("```mermaid", "", 1)
        if mindmap_content.endswith("```"):
            mindmap_content = mindmap_content[:-3]
    elif mindmap_content.startswith("```"):
        mindmap_content = mindmap_content.replace("```", "", 1)
        if mindmap_content.endswith("```"):
            mindmap_content = mindmap_content[:-3]

    mindmap_content = mindmap_content.strip()
    final_docs["mindmap.md"] = f"```mermaid\n{mindmap_content}\n```"

    # Securely write to disk
    for filename, content in final_docs.items():
        filepath = os.path.join(folder_path, filename)
        FileWriteTool.invoke({"file_path": filepath, "content": content})
        console.print(f"  [green]->[/green] Saved {filename}")

    return {"final_docs": final_docs}


# ============================================================================
# 5. Build and Compile the Graph
# ============================================================================
def build_agent() -> StateGraph:
    workflow = StateGraph(AgentState)

    workflow.add_node("Indexer", indexer_node)
    workflow.add_node("Analyst", analyst_node)
    workflow.add_node("Researcher", researcher_node)
    workflow.add_node("Writer", writer_node)

    workflow.add_edge(START, "Indexer")
    workflow.add_edge("Indexer", "Analyst")
    workflow.add_edge("Analyst", "Researcher")
    workflow.add_edge("Researcher", "Writer")
    workflow.add_edge("Writer", END)

    return workflow.compile()


if __name__ == "__main__":
    try:
        app = build_agent()

        if len(sys.argv) > 1:
            target_dir = sys.argv[1]
        else:
            target_dir = input("Enter the folder path to analyze: ").strip()

        if not os.path.exists(target_dir):
            console.print(
                "[bold red]Error: The specified folder does not exist.[/bold red]"
            )
            sys.exit(1)

        initial_state = {
            "folder_path": target_dir,
            "files": [],
            "file_summaries": {},
            "research_context": "",
            "final_docs": {},
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

        with console.status(
            "[bold green]Analysis in progress...[/bold green]", spinner="dots"
        ):
            result = app.invoke(initial_state)

        console.print(
            "\n[bold cyan]=======================================================[/bold cyan]"
        )
        console.print("[bold green]Execution Finished.[/bold green]")
        console.print(
            "Check the target directory for the generated documentation files:"
        )
        console.print(" - [bold]README.md[/bold]")
        console.print(" - [bold]IMPROVEMENTS.md[/bold]")
        console.print(" - [bold]mindmap.md[/bold]")
        console.print(
            "[bold cyan]=======================================================[/bold cyan]\n"
        )

    except KeyboardInterrupt:
        console.print(
            "\n[bold yellow]Analysis interrupted by user (Ctrl+C). Exiting gracefully...[/bold yellow]"
        )
        sys.exit(0)
    except Exception as e:
        console.print(f"\n[bold red]An unexpected error occurred: {e}[/bold red]")
        sys.exit(1)
