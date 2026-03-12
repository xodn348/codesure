# codesure: VULN CWE-502 HIGH
import pickle

data = pickle.loads(user_supplied_bytes)
# codesure: SAFE
import json

data = json.loads(user_supplied_string)
