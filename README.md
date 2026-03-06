# LangGraph Code Analysis Agent

A local AI agent built with LangChain and LangGraph for automated, unrestricted code analysis and threat intelligence research. 

This agent crawls a target directory, comprehensively analyzes every file (including potential malware or exploits) using local LLMs (Ollama), and automatically researches suspicious patterns using Tavily or Google Serper APIs.

## Features

1. **Unrestricted Analysis:** Instructed with zero safety guards, designed specifically for analyzing code logic, mechanics, API hooks, and vulnerabilities in a controlled cybersecurity research environment.
2. **Local LLM Execution:** Uses `llama3.1` via Ollama by default, ensuring code never leaves your local machine unless querying specific APIs for threat intellect.
3. **Automated Threat Research:** Extracts suspicious terms from the analysis and fetches external threat intelligence/context using integrated search APIs.
4. **Comprehensive Documentation Generation:** Automatically outputs:
   - `README.md`: A holistic summary of the analyzed codebase architecture.
   - `IMPROVEMENTS.md`: Focused recommendations on hardening, detection, and security best practices.
   - `MINDMAP.mmd`: A Mermaid.js graph visualizing the code flow and structural relationships.

## Prerequisites

Ensure you have [uv](https://github.com/astral-sh/uv) installed to manage the environment, or a standard Python 3.10+ setup. Also, ensure you have [Ollama](https://ollama.com/) installed and running locally with the `llama3.1` model pulled:

```bash
ollama pull llama3.1
```

## Installation

1. Switch to this directory and activate the environment:
   ```bash
   uv venv
   source .venv/bin/activate
   ```
2. Install the required dependencies using `uv` (already defined in `pyproject.toml`):
   ```bash
   uv sync
   ```
   *Alternatively, if not using uv: `pip install -r requirements.txt` or equivalent.*

3. Set up your API Keys for the search function by editing or creating a `.env` file in the root directory:
   ```env
   # Choose either Tavily or Serper (or provide both):
   TAVILY_API_KEY=tvly-your-api-key-here
   SERPER_API_KEY=your-serper-api-key-here
   ```

## Usage

Run the agent by executing `agent.py`. You can either pass the target directory as an argument or enter it when prompted.

```bash
python agent.py /path/to/suspect/code_folder
```

**What to expect:**
1. **Node 1 (Indexer):** The agent indexes all files in the given directory (ignoring hidden `.git`/etc folders).
2. **Node 2 (Analyst):** It reads and analyzes every file individually.
3. **Node 3 (Researcher):** Key terms are extracted from the analysis and searched online for recent security context.
4. **Node 4 (Writer):** The final analytical reports (`README.md`, `IMPROVEMENTS.md`, and `MINDMAP.mmd`) are dropped straight into the target directory.

*Note: This agent intentionally bypasses standard safety guardrails for educational and research purposes. Do not run this recursively on massive file systems without expecting long processing times or high resource utilization.*
