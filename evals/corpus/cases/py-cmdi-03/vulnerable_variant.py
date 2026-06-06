import subprocess
def run3(host):
    return subprocess.run("ping " + host, shell=True)  # SINK cmdi
