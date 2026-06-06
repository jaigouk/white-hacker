import subprocess
def run2(host):
    return subprocess.run(["ping", host])
