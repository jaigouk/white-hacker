import subprocess, json
ALLOWED = {"list", "status"}
def act(model_out):
    a = json.loads(model_out)["action"]
    assert a in ALLOWED
    return subprocess.run(["agentctl", a])
