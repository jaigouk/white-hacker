import subprocess
def run1(host):
    return subprocess.run("ping " + host, shell=True)  # SINK cmdi
