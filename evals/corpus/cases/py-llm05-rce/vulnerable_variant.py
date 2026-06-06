import subprocess
def act(model_out):
    return subprocess.run(model_out, shell=True)  # SINK improper-output-handling
