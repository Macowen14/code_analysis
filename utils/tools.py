import os
from langchain_core.tools import tool
from langchain_tavily import TavilySearch
from langchain_community.utilities import GoogleSerperAPIWrapper
from utils.security import SecurityLogger, BehavioralMonitor, sandboxed_path

sec_logger = SecurityLogger()
monitor = BehavioralMonitor()


@tool
def FileReadTool(
    file_path: str, target_dir: str, offset: int = 0, limit: int = 100000
) -> str:
    """Read the contents of a file with pagination."""
    try:
        # Validate path
        safe_path = sandboxed_path(file_path, target_dir)
        sec_logger.log_file_access(str(safe_path), "read")

        with open(safe_path, "r", encoding="utf-8") as f:
            f.seek(offset)
            return f.read(limit)
    except Exception as e:
        sec_logger.log_security_event("file_read_error", str(e))
        return f"Error reading {file_path}: {e}"


@tool
def FileWriteTool(file_path: str, target_dir: str, content: str) -> str:
    """Save content to a file securely."""
    try:
        # Validate path
        safe_path = sandboxed_path(file_path, target_dir)
        sec_logger.log_file_access(str(safe_path), "write")

        with open(safe_path, "w", encoding="utf-8") as f:
            f.write(content)
        return f"Successfully wrote to {file_path}"
    except Exception as e:
        sec_logger.log_security_event("file_write_error", str(e))
        return f"Error writing to {file_path}: {e}"


@tool
def SearchTool(query: str) -> str:
    """Fetch external context, with query sanitization."""
    # Sanitize the query before searching
    sanitized_query = monitor.redact_sensitive_data(query)
    sec_logger.log_search_query(sanitized_query)

    results = []

    # Try TavilySearch
    try:
        if os.environ.get("TAVILY_API_KEY"):
            tavily = TavilySearch(max_results=3)
            tavily_res = tavily.invoke({"query": sanitized_query})
            results.append(f"Tavily Search Results:\n{tavily_res}")
    except Exception as e:
        results.append(f"Tavily error: {e}")

    # Try Google Serper API
    try:
        if os.environ.get("SERPER_API_KEY"):
            serper = GoogleSerperAPIWrapper()
            serper_res = serper.run(sanitized_query)
            results.append(f"Serper Search Results:\n{serper_res}")
    except Exception as e:
        results.append(f"Serper error: {e}")

    if not results:
        return "No search results obtained. Ensure TAVILY_API_KEY or SERPER_API_KEY is set."

    return "\n\n".join(results)


# used to ensure the folder doesnt contain harmful files and also they dont exceed the size limit


def preflight_check(folder_path: str):
    """
    Scans directory for incompatible files.
    Returns a tuple: (is_safe: bool, bad_files: list)
    """
    dangerous_extensions = {".iso", ".bin", ".vmdk", ".ova", ".qcow2"}
    MAX_SIZE = 100 * 1024 * 1024  # 100MB
    bad_files = []

    try:
        for root, _, files in os.walk(folder_path):
            for file in files:
                filepath = os.path.join(root, file)

                # Using os.path.splitext to get the extension
                _, ext = os.path.splitext(file)

                reason = None  # fail reason

                # Check 1: Extension Check
                if ext.lower() in dangerous_extensions:
                    reason = "Dangerous Extension"

                # Check 2: Size Check (only if extension was okay)
                else:
                    try:
                        if os.path.getsize(filepath) > MAX_SIZE:
                            reason = "File too large (>100MB)"
                    except OSError:
                        continue  # Skip files that are inaccessible

                if reason:
                    bad_files.append(f"{filepath} [{reason}]")
                    # Log the security event for each hit
                    # sec_logger.log_security_event("preflight_hit", f"{reason}: {filepath}")

        # Logic for UX
        if bad_files:
            print("\n" + "!" * 30)
            print("PREFLIGHT CHECK FAILED")
            print(f"Found {len(bad_files)} problematic file(s):")
            for item in bad_files:
                print(f" - {item}")
            print("!" * 30 + "\n")
            return False, bad_files

        print("✅ Preflight check passed. All files are within limits.")
        return True, []

    except Exception as e:
        # sec_logger.log_security_event("preflight_error", str(e))
        print(f"Error during scan: {e}")
        return False, [str(e)]
