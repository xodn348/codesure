# codesure: VULN CWE-78 CRITICAL
import subprocess

subprocess.call(user_input, shell=True)
# codesure: SAFE
subprocess.call(["ls", "-la"], shell=False)
