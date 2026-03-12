# codesure: SAFE
import subprocess

result = subprocess.run(["ls", "-la"], capture_output=True, shell=False)
