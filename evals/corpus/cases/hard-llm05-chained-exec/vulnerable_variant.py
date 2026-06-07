def plan_step(llm, task):
    cmd = llm.complete(f"Return a shell command to: {task}")
    return {"command": cmd}


def run_plan(step):
    import subprocess
    return subprocess.run(step["command"], shell=True, capture_output=True)
