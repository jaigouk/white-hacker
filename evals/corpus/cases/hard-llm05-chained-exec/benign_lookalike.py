ACTIONS = {"build": ["make"], "test": ["pytest"]}


def plan_step(llm, task):
    choice = llm.complete(f"Pick one of build|test for: {task}").strip()
    return {"action": choice if choice in ACTIONS else "test"}


def run_plan(step):
    import subprocess
    return subprocess.run(ACTIONS[step["action"]], capture_output=True)
