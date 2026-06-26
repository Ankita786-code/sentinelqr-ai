import json
import os

# -----------------------------
# Load Blacklist Once
# -----------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BLACKLIST_PATH = os.path.join(BASE_DIR, "malicious_domains.json")

try:
    with open(BLACKLIST_PATH, "r") as file:
        data = json.load(file)

    BLACKLIST = set(
        domain.lower()
        for domain in data.get("malicious_domains", [])
    )

except Exception:
    BLACKLIST = set()


# -----------------------------
# Check Domain
# -----------------------------

def check_blacklist(domain):
    """
    Returns True if domain exists
    in the blacklist.
    """

    return domain.lower() in BLACKLIST