# codesure: SAFE
import subprocess

output = subprocess.run(["git", "log", "--oneline"], capture_output=True, shell=False)
