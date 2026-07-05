import asyncio
import os
from environment import SentinelSOCEnv
from models import IncidentAction

def grade(agent_fn, task: str = "easy") -> float:
    """
    Mandatory Hackathon Grader Interface.
    
    Args:
        agent_fn: A function that takes an observation and returns a dict/Action.
        task: String key ("easy", "medium", "hard").
        
    Returns:
        float: Normalized score between 0.0 and 1.0.
    """
    # 1. Initialize Environment
    env = SentinelSOCEnv()
    obs = env.reset(task=task)
    
    MAX_STEPS = {
        "easy": 10,
        "medium": 15,
        "hard": 20
    }.get(task, 10)
    
    # 2. Execution Loop
    last_tool_result = ""
    for _ in range(MAX_STEPS):
        # The agent_fn must return an IncidentAction or a compatible dict.
        # Pass last_tool_result if the agent accepts it (backward-compatible check).
        import inspect
        sig = inspect.signature(agent_fn)
        if "last_tool_result" in sig.parameters:
            action_dict = agent_fn(obs.model_dump(), last_tool_result=last_tool_result)
        else:
            action_dict = agent_fn(obs.model_dump())

        # Convert dict to IncidentAction if necessary
        if isinstance(action_dict, dict):
            action = IncidentAction(**action_dict)
        else:
            action = action_dict

        obs, reward, done, info = env.step(action)
        last_tool_result = info.get("tool_result", "")

        if done:
            break

    # 3. Final Deterministic Grade
    return env.grade()

def grade_all_tasks(agent_fn) -> dict:
    """
    Evaluates the agent across all difficulty levels.
    """
    import numpy as np
    results = {}
    for task in ("easy", "medium", "hard"):
        results[task] = grade(agent_fn, task=task)
    results["overall"] = float(np.mean(list(results.values())))
    return results

if __name__ == "__main__":
    # Local verification script
    from baseline import baseline_agent
    
    print("--- Sentinel-SOC Local Validation ---")
    results = grade_all_tasks(baseline_agent)
    for task, score in results.items():
        print(f"Task: {task.upper():<10} | Score: {score:.3f}")
