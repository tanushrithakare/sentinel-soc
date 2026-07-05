import sys
import os

# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

# Ensure project root (one level up) is in path
root_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if root_path not in sys.path:
    sys.path.insert(0, root_path)

from fastapi import FastAPI, HTTPException, Query
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from environment import SentinelSOCEnv
from models import IncidentAction, IncidentObs, AnalyticsReport, KillChainPhaseStats
import gradio as gr
from server.gradio_ui import create_gradio_ui, CSS, JS_FORCE_DARK, THEME

app = FastAPI()

# Per-request environment storage (prevents state sharing between concurrent requests)
_env_instances = {}  # Maps session_id to environment


def get_or_create_env(session_id: str = "default") -> SentinelSOCEnv:
    """Get or create environment instance for this session."""
    if session_id not in _env_instances:
        _env_instances[session_id] = SentinelSOCEnv()
    return _env_instances[session_id]


@app.get("/health")
def health():
    return {"status": "healthy", "service": "sentinel-soc"}


@app.post("/reset", response_model=IncidentObs)
def reset(task: str = Query("easy", enum=["easy", "medium", "hard"])):
    # Create fresh environment for this reset (prevents state sharing between concurrent users)
    env = SentinelSOCEnv()
    _env_instances["default"] = env
    return env.reset(task=task)


@app.post("/step")
def step(action: IncidentAction):
    env = get_or_create_env()
    obs, reward, done, info = env.step(action)
    return {
        "observation": obs,
        "reward": float(reward),
        "done": bool(done),
        "info": info
    }


@app.get("/state", response_model=IncidentObs)
def state():
    env = get_or_create_env()
    return env._get_obs()


@app.post("/grade")
def grade():
    env = get_or_create_env()
    score = env.grade()
    return {"score": score}


@app.get("/history")
def get_history():
    env = get_or_create_env()
    return {"history": env.history}


@app.get("/analytics", response_model=AnalyticsReport)
def analytics():
    """Return a structured analytics report for the current investigation session."""
    env = get_or_create_env()
    history = env.history

    # Kill chain phase completion map
    PHASE_TOOL_MAP = [
        ("Reconnaissance",  "query_logs",   0.10),
        ("Identification",  "extract_ioc",  0.30),
        ("Containment",     "inspect_file", 0.20),
        ("Remediation",     "apply_fix",    0.40),
    ]
    phase_stats: list[KillChainPhaseStats] = []
    for phase_name, tool_name, max_reward in PHASE_TOOL_MAP:
        earned = next(
            (h["reward"] for h in history if h["tool"] == tool_name and h["reward"] > 0),
            0.0,
        )
        phase_stats.append(
            KillChainPhaseStats(
                phase=phase_name,
                completed=earned > 0,
                tool_used=tool_name,
                reward_earned=round(earned, 2),
            )
        )

    total_steps = len(history)
    successful_steps = sum(1 for h in history if h["reward"] > 0)
    total_reward = round(sum(h["reward"] for h in history), 3)
    efficiency_score = round(total_reward / total_steps, 4) if total_steps > 0 else 0.0
    success_rate = round(successful_steps / total_steps, 4) if total_steps > 0 else 0.0

    # Per-tool call counts
    action_breakdown: dict[str, int] = {}
    for h in history:
        action_breakdown[h["tool"]] = action_breakdown.get(h["tool"], 0) + 1

    # Final grade only when the episode is done
    final_grade = round(env.grade(), 3) if (env.mitigated or env.steps_taken >= env.max_steps) else None

    return AnalyticsReport(
        task=env.task,
        total_steps=total_steps,
        steps_remaining=env.max_steps - env.steps_taken,
        kill_chain_phases=phase_stats,
        total_reward=total_reward,
        efficiency_score=efficiency_score,
        success_rate=success_rate,
        action_breakdown=action_breakdown,
        incident_resolved=env.mitigated,
        final_grade=final_grade,
    )

# --- Gradio UI Integration ---
ui_app = create_gradio_ui(server_url="http://localhost:7860")
# BUG 3 FIX: theme/css/js are direct keyword args of mount_gradio_app,
# NOT nested inside app_kwargs (which is reserved for FastAPI constructor args).
# Previously they were silently ignored, so the dark SOC theme never applied.
app = gr.mount_gradio_app(
    app,
    ui_app,
    path="/",
    theme=THEME,
    css=CSS,
    js=JS_FORCE_DARK,
)

def main():
    import uvicorn
    uvicorn.run("server.app:app", host="0.0.0.0", port=7860, reload=False)

if __name__ == "__main__":
    main()
