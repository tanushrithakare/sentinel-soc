import asyncio
import os
import re
from client import SentinelSOCClient
from models import IncidentAction

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
        # Look for suspicious external IPs (not 10.x or 192.168.x)
        matches = re.findall(r'(?:^|\s)((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?:\s|$|:)', logs)
        for ip in matches:
            octets = ip.split('.')
            # Skip internal ranges
            if not (octets[0] == '10' or (octets[0] == '192' and octets[1] == '168') or octets[0] == '172'):
                return ip
        return "unknown_ip"
    
    elif phase == "hard":
        # Look for suspicious domains (not in safe list)
        safe_domains = {'.com', '.amazonaws.com', '.google.com', 'cloudflare', 'okta', 'auth'}
        matches = re.findall(r'([\w-]+\.(?:cc|ru|xyz|tk|onion|io|biz|net))', logs)
        for domain in matches:
            if not any(safe in domain for safe in safe_domains):
                return domain
        # Fallback to any suspicious-looking domain
        match = re.search(r'([\w-]+\.(?:cc|ru|xyz|tk|onion))', logs)
        return match.group(1) if match else "unknown_domain"
    
    return "unknown_ioc"

def _extract_filename_from_logs(logs: str, code_snippet: str, phase: str) -> str:
    """
    Dynamically extract suspicious filename from logs based on scenario type.
    """
    if phase == "easy":
        # Look for .log files mentioned in logs as suspicious
        matches = re.findall(r'(\w+\.log)', logs + code_snippet)
        return matches[0] if matches else "app.log"
    
    elif phase == "medium":
        # Look for .py files in logs (database-related)
        matches = re.findall(r'([\w_]+\.py)', logs + code_snippet)
        for match in matches:
            if any(term in match.lower() for term in ['db', 'query', 'orm', 'dao', 'handler']):
                return match
        return matches[0] if matches else "db_utils.py"
    
    elif phase == "hard":
        # Look for vendor directory files
        matches = re.findall(r'(vendor/[\w/_.]+\.py)', logs + code_snippet)
        if matches:
            return matches[0]
        # Fallback to vendor pattern
        matches = re.findall(r'([\w_]+\.py)', code_snippet)
        for match in matches:
            if 'vendor' in code_snippet or 'auth' in match.lower() or 'crypto' in match.lower():
                return f"vendor/{match}"
        return "vendor/auth_lib.py"
    
    return "unknown_file"

def baseline_agent(obs: dict, task: str = "easy") -> dict:
    """
    State-aware baseline agent for standardized grading.
    Dynamically extracts IOCs from logs instead of hardcoding.
    """
    # 1. Determine Level (fall back to easy)
    phase = "easy"
    if "SQL" in obs['incident_thread'] or "192.168" in obs['logs']:
        phase = "medium"
    if "egress" in obs['incident_thread'] or "base64" in obs['code_snippet']:
        phase = "hard"

    # 2. Logic Gates (Grand Master sequence)
    if "Mitigated" in obs['status']:
        return {"reasoning": "Mission goal achieved.", "tool": "query_logs", "parameters": "heartbeat"}

    if "Initial" in obs['status'] or "Active" in obs['status']:
        if "High-confidence" not in obs['status'] and "CONFIRMED" not in obs['status']:
            # Gate 1: Logs first
            if phase == "easy":
                return {"reasoning": "Step 1: Discovering patterns in logs.", "tool": "query_logs", "parameters": "all"}
            elif phase == "medium":
                return {"reasoning": "Step 1: Monitoring DB traffic.", "tool": "query_logs", "parameters": "database"}
            else:
                return {"reasoning": "Step 1: Auditing network egress.", "tool": "query_logs", "parameters": "network"}
        
        if "Ready for Fix" not in obs['status'] and "Root Cause" not in obs['status']:
            # Gate 2: Extract IOC after logs (dynamically from logs)
            ioc = _extract_ioc_from_logs(obs['logs'], obs['code_snippet'], phase)
            if phase == "easy":
                return {"reasoning": f"Step 2: Confirming PRODUCTION leak {ioc}.", "tool": "extract_ioc", "parameters": ioc}
            elif phase == "medium":
                return {"reasoning": f"Step 2: Confirming Malicious IP source {ioc}.", "tool": "extract_ioc", "parameters": ioc}
            else:
                return {"reasoning": f"Step 2: Confirming Backdoor Domain {ioc}.", "tool": "extract_ioc", "parameters": ioc}

        if "Monitoring" not in obs['status']:
            # Gate 3: Inspect file (dynamically extracted)
            filename = _extract_filename_from_logs(obs['logs'], obs['code_snippet'], phase)
            if phase == "easy":
                return {"reasoning": f"Step 3: Finding root cause in {filename}.", "tool": "inspect_file", "parameters": filename}
            elif phase == "medium":
                return {"reasoning": f"Step 3: Finding vulnerable DB logic in {filename}.", "tool": "inspect_file", "parameters": filename}
            else:
                return {"reasoning": f"Step 3: Auditing compromised library {filename}.", "tool": "inspect_file", "parameters": filename}

        # Gate 4: Final Fix
        return {"reasoning": "Final Mitigation.", "tool": "apply_fix", "parameters": "rotate_and_mask" if phase == "easy" else "patch_sql" if phase == "medium" else "remove_backdoor"}

    return {"reasoning": "Default hunt.", "tool": "query_logs", "parameters": "status"}

async def run_baseline(task="easy"):
    print(f"Running Standardized Baseline on task: {task}")
    client = SentinelSOCClient("http://localhost:7860")
    try:
        obs = client.reset(task=task)
        print(f"Initial Phase: {obs.status}")
        
        # Simple loop using the baseline_agent function
        for i in range(5):
            action_dict = baseline_agent(obs.model_dump(), task=task)
            action = IncidentAction(**action_dict)
            res = client.step(action)
            obs = res['observation']
            print(f"Step {i+1}: {res['info']['tool_result']} (Reward: {res['reward']:.2f})")
            if res['done']: break
            
        final_score = client.grade()
        print(f"\nFinal Achievement Score (with efficiency): {final_score}")

    finally:
        client.close()

if __name__ == "__main__":
    import sys
    task_arg = sys.argv[1] if len(sys.argv) > 1 else "easy"
    asyncio.run(run_baseline(task=task_arg))
