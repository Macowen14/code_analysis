# Code Analysis Agent

## **Project Overview & Purpose**
The **Code Analysis Agent** is a high-performance, AI-driven tool designed for automated code inspection, dependency analysis, and security research in controlled environments. It leverages modern Python frameworks (e.g., LangChain, Ollama, Tavily) to:
- Parse and analyze codebases for structural, logical, and security-related patterns.
- Automate dependency resolution and vulnerability assessment.
- Execute controlled experiments in isolated environments (e.g., sandboxed LLM interactions).

**Key Use Cases**:
- **Security Research**: Identify potential vulnerabilities in Python projects (e.g., SSRF risks, prompt injection vectors).
- **Dependency Auditing**: Enforce strict version pinning and detect supply-chain risks.
- **Workflow Automation**: Integrate with CI/CD pipelines for pre-deployment code analysis.

---

## **Architecture & Key Components**
The agent is built on a modular architecture with the following core components:

### **1. Core Engine**
- **LangChain/LangGraph**: Orchestrates multi-step analysis workflows (e.g., code parsing → LLM evaluation → report generation).
- **Ollama Integration**: Enables local LLM inference for offline analysis (e.g., Llama3, Mistral).
- **Tavily Search**: Augments analysis with real-time threat intelligence (e.g., CVE lookups).

### **2. Dependency Management**
- **`uv` Package Manager**: Ensures reproducible builds via locked dependency versions (`uv.lock`).
- **Pydantic**: Validates configuration and input/output schemas.
- **Structlog**: Provides structured logging for auditing and debugging.

### **3. Network & Security Layer**
- **`aiohttp`**: Async HTTP client for external API interactions (e.g., Tavily, SerpAPI).
- **Network Policies**: Configurable allow/deny lists (e.g., `deny-networks = ["*"]` with exceptions for `127.0.0.1`).

### **4. Configuration & Extensibility**
- **Environment Variables**: Securely load API keys and settings via `python-dotenv`.
- **Plugin System**: Extend functionality with custom LangChain tools (e.g., static analysis, fuzzing).

---

## **Installation & Setup**
### **Prerequisites**
- Python `3.10`–`3.12` (see `requires-python` in `pyproject.toml`).
- `uv` (recommended) or `pip` for dependency management.
- Optional: Local LLM (e.g., Ollama) for offline analysis.

### **Steps**
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/your-repo/code-analysis-agent.git
   cd code-analysis-agent
   ```

2. **Install Dependencies**:
   - Using `uv` (recommended):
     ```bash
     uv sync
     ```
   - Using `pip`:
     ```bash
     pip install -e .
     ```

3. **Configure Environment Variables**:
   - Copy `.env.example` to `.env` and populate with API keys (e.g., `TAVILY_API_KEY`, `SERPAPI_KEY`).
   - Example:
     ```ini
     TAVILY_API_KEY=your_key_here
     OLLAMA_MODEL=llama3
     ```

4. **Verify Installation**:
   ```bash
   python -c "from code_analysis import Agent; print('Agent loaded successfully')"
   ```

---

## **Configuration Options**
### **Environment Variables**
| Variable               | Description                                                                 | Default          |
|------------------------|-----------------------------------------------------------------------------|------------------|
| `TAVILY_API_KEY`       | API key for Tavily search (threat intelligence).                            | `None`           |
| `SERPAPI_KEY`          | API key for SerpAPI (Google search results).                                | `None`           |
| `OLLAMA_MODEL`         | Local LLM model name (e.g., `llama3`, `mistral`).                           | `llama3`         |
| `LOG_LEVEL`            | Logging verbosity (`DEBUG`, `INFO`, `WARNING`, `ERROR`).                    | `INFO`           |
| `ALLOW_NETWORK`        | Comma-separated list of allowed domains (e.g., `tavily.com,serpapi.com`).   | `127.0.0.1`      |

### **Model Settings**
Configure LLM behavior in `config.yaml` (or via CLI):
```yaml
llm:
  temperature: 0.2      # Lower for deterministic outputs
  max_tokens: 4096      # Adjust based on model limits
  tools:                # Enable/disable LangChain tools
    - "python_repl"     # Caution: High-risk for code execution
    - "tavily_search"
```

---

## **Usage Examples & Workflow**
### **1. Basic Code Analysis**
Analyze a Python file for security risks:
```bash
python -m code_analysis analyze --file target.py
```
**Output**:
- Dependency graph.
- Potential vulnerabilities (e.g., unsafe `eval()` usage).
- LLM-generated remediation suggestions.

### **2. Dependency Audit**
Check for outdated or vulnerable dependencies:
```bash
python -m code_analysis audit --path /path/to/project
```
**Output**:
- CVSS scores for vulnerable packages.
- Version upgrade recommendations.

### **3. Interactive LLM Analysis**
Start an interactive session with the agent:
```bash
python -m code_analysis chat --model ollama
```
**Example Prompt**:
```
Analyze this code for SSRF risks:
```python
import aiohttp
url = input("Enter URL: ")
await aiohttp.get(url)
```
```

### **4. Batch Processing**
Analyze multiple repositories in parallel:
```bash
python -m code_analysis batch --repos repo1/ repo2/ --output reports/
```

---

## **Workflow**
1. **Input**: Provide code (file/directory) or a Git repository URL.
2. **Parsing**: The agent extracts dependencies, imports, and code structure.
3. **Analysis**:
   - Static analysis (e.g., AST parsing for unsafe functions).
   - Dynamic analysis (e.g., LLM evaluation of code logic).
   - Network checks (e.g., SSRF risks in HTTP clients).
4. **Reporting**: Generate JSON/HTML reports with findings and remediations.

---

## **Next Steps**
- **Extend**: Add custom LangChain tools for domain-specific analysis.
- **Automate**: Integrate with GitHub Actions or GitLab CI.
- **Hardening**: Review `IMPROVEMENTS.md` for security best practices.
```

This `README.md` provides a **technical yet accessible** overview of the project while adhering to the constraints (no vulnerability details).