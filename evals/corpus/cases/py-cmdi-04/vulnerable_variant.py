import subprocess
def run4(host):
    return subprocess.run("ping " + host, shell=True)  # SINK cmdi
