import subprocess
from _support_planner import model_suggestion


def run_task(llm, task):
    s = model_suggestion(llm, task)
    return subprocess.run(s, shell=True, capture_output=True)
