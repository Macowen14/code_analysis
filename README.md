# LangGraph Code Analysis Agent - Technical Architecture Documentation

## System Overview

A LangGraph-based autonomous code analysis system designed for **unrestricted cybersecurity research** in controlled environments. This tool implements a zero-safety-guard approach to analyze potentially malicious code, exploits, and vulnerabilities without AI content filtering restrictions.

## Core Architecture

### System Components

#### 1. **Workflow Engine (LangGraph)**
- **Type**: Directed Acyclic Graph (DAG) with sequential execution
- **Nodes**: 4-stage pipeline with state propagation
- **State Management**: TypedDict-based structured state flow

#### 2. **Processing Pipeline**
```
Directory → Indexer → Analyst → Researcher → Writer
                    ↓          ↓
               Local LLM   External APIs
```

### Node Specifications

#### **Node 1: Indexer**
- **Function**: File system crawler with `.git` exclusion
- **Mechanics**: Non-recursive directory scanning
- **Output**: List of file paths for analysis

#### **Node 2: Analyst**
- **Core**: Local LLM analysis via Ollama (llama3.1 model)
- **Processing**: Per-file sequential analysis
- **Capabilities**: Code pattern recognition, vulnerability detection, logic analysis

#### **Node 3: Researcher**
- **Function**: External threat intelligence gathering
- **APIs**: Tavily Search API (primary) or Google Serper API (fallback)
- **Trigger**: Suspicious pattern extraction from Analyst node
- **Output**: Consolidated research context

#### **Node 4: Writer**
- **Function**: Multi-format documentation generation
- **Outputs**: Three distinct markdown reports with different analytical focuses

## Technical Specifications

### Dependencies & Requirements

#### **Core Frameworks**
- **Python**: ≥3.10
- **LangChain Ecosystem**: Core, Community, Ollama, Tavily integrations
- **LangGraph**: ≥1.0.10 for stateful multi-agent orchestration

#### **Search Integrations**
- **Tavily-Python**: ≥0.7.22 (AI-optimized search)
- **Google-Search-Results**: ≥2.4.2 (traditional search fallback)

#### **Utility Libraries**
- **pathspec**: ≥1.0.4 (gitignore-style pattern matching)
- **python-dotenv**: ≥1.2.2 (environment management)
- **rich**: ≥13.0.0 (terminal formatting)

### State Management Structure

```python
class AgentState(TypedDict):
    folder_path: str          # Target directory path
    files: List[str]         # Discovered file paths
    file_summaries: Dict[str, str]  # LLM analysis per file
    research_context: str    # External search results
    final_docs: Dict[str, str]  # Generated documentation
```

## Functional Capabilities

### 1. **Unrestricted Code Analysis**
- Bypasses standard AI safety guardrails
- Processes all file types without content filtering
- Local LLM processing for sensitive code isolation

### 2. **Threat Intelligence Integration**
- Automated suspicious pattern extraction
- Dual-search strategy (Tavily + Google Serper)
- Contextual vulnerability research

### 3. **Multi-format Reporting**
- Technical architecture documentation
- Vulnerability and exploit analysis
- Dependency and supply chain risk assessment

## Security Architecture

### **Intentional Design Choices**
1. **No Safety Guards**: Explicit removal of content filtering for malware analysis
2. **Local Processing**: Ollama integration keeps sensitive code analysis offline
3. **Controlled External Calls**: Search APIs only triggered by specific patterns

### **Potential Attack Vectors**

#### **1. Input Handling Risks**
- Path traversal vulnerabilities in directory targeting
- Symlink following without validation
- Resource exhaustion via recursive scanning

#### **2. External API Risks**
- Information disclosure via search queries
- API key exposure through `.env` files
- Rate limiting absence for external services

#### **3. Local Execution Risks**
- Model prompt injection vulnerabilities
- File overwrite without confirmation
- Environment pollution from analyzed code

### **Defensive Gaps**
- No sandboxing or isolation mechanisms
- Missing input sanitization for file paths
- Absence of output validation
- No authentication for Ollama endpoint

## Operational Requirements

### **Environment Setup**
```bash
# Prerequisites
Python 3.10+
Ollama running locally with llama3.1 model
UV package manager

# Installation
uv sync
cp .env.example .env  # Configure API keys
```

### **API Configuration**
- **Tavily API**: `tvly-*` format key in `.env`
- **Google Serper API**: Alternative search provider
- **Ollama**: Local HTTP endpoint (default: http://localhost:11434)

### **Execution Flow**
1. **Initialization**: Environment validation and API key loading
2. **Indexing**: Target directory scanning with pattern exclusion
3. **Analysis**: Sequential file processing via local LLM
4. **Research**: External API calls for threat intelligence
5. **Documentation**: Report generation in target directory

## Threat Model

### **Intended Use Cases**
- Malware reverse engineering in isolated environments
- Exploit code analysis without content restrictions
- Vulnerability research with external context gathering
- Supply chain attack simulation and analysis

### **Containment Requirements**
- Network segmentation for external API calls
- File system permissions limiting
- Resource quota enforcement
- Activity monitoring and logging

## Deployment Considerations

### **Network Requirements**
- Outbound HTTP/HTTPS for search APIs
- Local network access for Ollama endpoint
- No inbound requirements

### **Storage Requirements**
- Read access to target analysis directory
- Write access for report generation
- Temporary storage for LLM processing

### **Compute Requirements**
- Sufficient RAM for llama3.1 model inference
- CPU resources for file processing
- Network bandwidth for external research

## Limitations & Constraints

### **Technical Limitations**
- Hardcoded to llama3.1 model (no parameterization)
- Non-recursive directory scanning only
- Sequential file processing (no parallelism)
- Limited error recovery mechanisms

### **Security Constraints**
- No authentication for any components
- Missing input validation layers
- Absence of audit trail generation
- No rate limiting or throttling

## Development Roadmap

### **Planned Enhancements**
1. **Security Hardening**
   - Input validation and sanitization
   - Sandboxed execution environment
   - Audit logging and activity monitoring

2. **Functional Improvements**
   - Parallel file processing
   - Recursive directory scanning option
   - Model parameterization support

3. **Operational Features**
   - Docker containerization
   - CLI argument expansion
   - Configuration file support

## Disclaimer

**WARNING**: This tool is designed exclusively for controlled cybersecurity research environments. It intentionally removes safety guardrails and should never be deployed in production systems or used with untrusted code without proper containment measures. External API calls may expose sensitive information to third-party services.

---

*This documentation generated by the LangGraph Code Analysis Agent v0.1.0*