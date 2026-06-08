import subprocess
from _support_planner import model_suggestion

ALLOWED = {"build": ["make"], "test": ["pytest"]}


def run_task(llm, task):
    s = model_suggestion(llm, task).strip()
    return subprocess.run(ALLOWED.get(s, ["true"]), capture_output=True)
