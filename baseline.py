import asyncio
import os
import re
from client import SentinelSOCClient
from models import IncidentAction, IncidentObs

def _extract_ioc_from_logs(logs: str, code_snippet: str, phase: str) -> str:
    """
    Dynamically extract IOC from logs based on scenario type.
    Falls back to generic pattern if not found.
    """
    if phase == "easy":
        # Look for sk_live keys (production credentials)
        match = re.search(r'sk_live_\w{10,}', logs)
        if match:
            return match.group(0)
        # Fallback: sk_test (less preferred)
        match = re.search(r'sk_test_\w{10,}', logs)
        return match.group(0) if match else "sk_live_unknown"
    
    elif phase == "medium":
        # BUG 5 FIX: medium logs contain multiple external IPs (target + decoy).
        # The target IP is specifically the one on the same line as the SQL payload.
        # Per-line correlation ensures we pick the attacker IP, not the decoy.
        for line in logs.splitlines():
            if re.search(r'(?:UNION|SELECT|DROP|INSERT|injection)', line, re.IGNORECASE):
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                if ip_match:
                    return ip_match.group(1)
        # Fallback: first non-RFC-1918 external IP
        all_ips = re.findall(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', logs)
        for ip in all_ips:
            octets = ip.split('.')
            if not (octets[0] == '10' or
                    (octets[0] == '192' and octets[1] == '168') or
                    octets[0] == '172'):
                return ip
        return "unknown_ip"
    
    elif phase == "hard":
        # Look for UNAUTHORIZED domain in network logs — must match the specific
        # (UNAUTHORIZED) marker to avoid selecting BLOCKED decoy domains.
        match = re.search(r'-> ([\w.-]+\.(?:cc|ru|xyz|tk|onion|io|biz|net)):\d+ \(UNAUTHORIZED\)', logs)
        if match:
            return match.group(1)
        # Fallback: decode base64 payload from code snippet if present
        b64_match = re.search(r'base64\.b64decode\("([A-Za-z0-9+/=]+)"\)', code_snippet)
        if b64_match:
            import base64 as _b64
            try:
                return _b64.b64decode(b64_match.group(1)).decode()
            except Exception:
                pass
        # Last resort: any suspicious domain from logs
        match = re.search(r'([\w-]+\.(?:cc|ru|xyz|tk|onion))', logs)
        return match.group(1) if match else "unknown_domain"
    
# Module-level cache: baseline_agent stores the last query_logs tool result
# so that _extract_filename_from_logs can use it even without API changes.
_last_tool_result: str = ""

def _extract_filename_from_logs(logs: str, code_snippet: str, phase: str) -> str:
    """
    Dynamically extract suspicious filename from logs based on scenario type.
    Also checks the cached query_logs tool result which explicitly names the target file.
    """
    # The query_logs tool result always mentions the target file:
    #   easy:   "...credential pattern observed in {target_file}..."
    #   medium: "...Anomalous SQL patterns detected in {target_file}..."
    #   hard:   "...Suspicious imports detected in {target_file}..."
    # Extract from the cached tool result first — most reliable signal.
    all_text = logs + "\n" + code_snippet + "\n" + _last_tool_result

    if phase == "easy":
        # Prefer CRITICAL log-bracket pattern: CRITICAL [filename.log]:
        match = re.search(r'CRITICAL \[([\w./]+\.log)\]', logs)
        if match:
            return match.group(1)
        # Fallback: any .log file mentioned
        matches = re.findall(r'([\w_]+\.log)', all_text)
        return matches[0] if matches else "app.log"

    elif phase == "medium":
        # The tool result says "detected in <file>" — extract that first
        tr_match = re.search(r'detected in ([\w_/]+\.py)', _last_tool_result)
        if tr_match:
            return tr_match.group(1)
        # Fallback: look for .py files with DB-related names in all text
        matches = re.findall(r'([\w_]+\.py)', all_text)
        for match in matches:
            if any(term in match.lower() for term in ['db', 'query', 'orm', 'dao', 'handler']):
                return match
        return matches[0] if matches else "db_utils.py"

    elif phase == "hard":
        # The tool result says "detected in <vendor/file>" — extract that first
        tr_match = re.search(r'detected in ([\w_/]+\.py)', _last_tool_result)
        if tr_match:
            return tr_match.group(1)
        # Fallback: vendor directory files from code snippet
        matches = re.findall(r'(vendor/[\w/_.]+\.py)', all_text)
        if matches:
            return matches[0]
        # Fallback: vendor file named in code snippet comment
        match = re.search(r'# (vendor/[\w.]+)', code_snippet)
        if match:
            return match.group(1)
        matches = re.findall(r'([\w_]+\.py)', code_snippet)
        for match in matches:
            if 'vendor' in code_snippet or 'auth' in match.lower() or 'crypto' in match.lower():
                return f"vendor/{match}"
        return "vendor/auth_lib.py"

    return "unknown_file"

def baseline_agent(obs: dict, task: str = "easy", last_tool_result: str = "") -> dict:
    """
    State-aware baseline agent for standardized grading.
    Dynamically extracts IOCs from logs instead of hardcoding.

    Args:
        obs: Current observation dict.
        task: Task difficulty key ("easy", "medium", "hard").
        last_tool_result: The tool_result string returned by the last env.step() call.
                          Used to extract the target filename from query_logs output.
    """
    global _last_tool_result
    if last_tool_result:
        _last_tool_result = last_tool_result

    # 1. Determine Level (fall back to easy)
    phase = "easy"
    # Check both incident_thread AND logs — the thread header may not contain phase keywords
    # until after query_logs is called, so we also scan the logs for SQL/network indicators.
    logs_and_thread = obs['incident_thread'] + obs['logs']
    if "SQL" in logs_and_thread or "UNION" in obs['logs'] or "INSERT" in obs['logs'] or "database" in obs['incident_thread'].lower():
        phase = "medium"
    if "egress" in obs['incident_thread'] or "base64" in obs['code_snippet'] or "NETWORK:" in obs['logs']:
        phase = "hard"

    # 2. Logic Gates (Grand Master sequence)
    if "Mitigated" in obs['status']:
        return {"reasoning": "Mission goal achieved.", "tool": "query_logs", "parameters": "heartbeat"}

    if "Active" in obs['status']:
        thread = obs['incident_thread']

        # Gate 1 — Phase: Reconnaissance (no logs reviewed yet)
        if "No log data reviewed yet" in thread:
            if phase == "easy":
                return {"reasoning": "Step 1: Discovering patterns in logs.", "tool": "query_logs", "parameters": "all"}
            elif phase == "medium":
                return {"reasoning": "Step 1: Monitoring DB traffic.", "tool": "query_logs", "parameters": "database"}
            else:
                return {"reasoning": "Step 1: Auditing network egress.", "tool": "query_logs", "parameters": "network"}

        # Gate 2 — Phase: Identification (logs reviewed, IOC not yet extracted)
        if "Suspicious indicators detected" in thread:
            ioc = _extract_ioc_from_logs(obs['logs'], obs['code_snippet'], phase)
            if phase == "easy":
                return {"reasoning": f"Step 2: Confirming PRODUCTION leak {ioc}.", "tool": "extract_ioc", "parameters": ioc}
            elif phase == "medium":
                return {"reasoning": f"Step 2: Confirming Malicious IP source {ioc}.", "tool": "extract_ioc", "parameters": ioc}
            else:
                return {"reasoning": f"Step 2: Confirming Backdoor Domain {ioc}.", "tool": "extract_ioc", "parameters": ioc}

        # Gate 3 — Phase: Containment (IOC confirmed, source file not yet isolated)
        if "Source file not yet isolated" in thread:
            filename = _extract_filename_from_logs(obs['logs'], obs['code_snippet'], phase)
            if phase == "easy":
                return {"reasoning": f"Step 3: Finding root cause in {filename}.", "tool": "inspect_file", "parameters": filename}
            elif phase == "medium":
                return {"reasoning": f"Step 3: Finding vulnerable DB logic in {filename}.", "tool": "inspect_file", "parameters": filename}
            else:
                return {"reasoning": f"Step 3: Auditing compromised library {filename}.", "tool": "inspect_file", "parameters": filename}

        # Gate 4 — Phase: Remediation (both IOC and file confirmed)
        if "Incident ready for remediation" in thread:
            return {"reasoning": "Final Mitigation.", "tool": "apply_fix",
                    "parameters": "rotate_and_mask" if phase == "easy" else "patch_sql" if phase == "medium" else "remove_backdoor"}

    return {"reasoning": "Default hunt.", "tool": "query_logs", "parameters": "status"}

async def run_baseline(task="easy"):
    print(f"Running Standardized Baseline on task: {task}")
    client = SentinelSOCClient("http://localhost:7860")
    try:
        obs = client.reset(task=task)
        print(f"Initial Phase: {obs.status}")
        
        # Simple loop using the baseline_agent function
        last_result = ""
        for i in range(5):
            action_dict = baseline_agent(obs.model_dump(), task=task, last_tool_result=last_result)
            action = IncidentAction(**action_dict)
            res = client.step(action)
            # BUG 1 FIX: client.step() returns a raw dict; wrap observation back
            # into IncidentObs so obs.model_dump() works on the next iteration.
            obs = IncidentObs(**res['observation'])
            last_result = res['info'].get('tool_result', '')
            print(f"Step {i+1}: {last_result} (Reward: {res['reward']:.2f})")
            if res['done']: break
            
        final_score = client.grade()
        print(f"\nFinal Achievement Score (with efficiency): {final_score}")

    finally:
        client.close()

if __name__ == "__main__":
    import sys
    task_arg = sys.argv[1] if len(sys.argv) > 1 else "easy"
    asyncio.run(run_baseline(task=task_arg))
