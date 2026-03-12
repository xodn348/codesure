# codesure: VULN CWE-78 CRITICAL
import subprocess

subprocess.run(user_command, shell=True)
# codesure: SAFE
subprocess.run(["grep", "-r", "pattern"], shell=False)
