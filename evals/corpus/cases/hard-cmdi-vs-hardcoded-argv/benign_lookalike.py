import subprocess


def disk_free():
    return subprocess.run(["df", "-h"], capture_output=True).stdout
