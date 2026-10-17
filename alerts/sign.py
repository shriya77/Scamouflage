"""Role D owns this file. FAKE STATION: replace the body, keep the signature.

sign(alert) -> same dict plus "sig" (base64 str) and "key_id" (str).
The real one signs with Ed25519 (CPACF-accelerated) - never commit the key.
"""


def sign(alert: dict) -> dict:
    alert = dict(alert)
    alert["sig"] = ""
    alert["key_id"] = "fake"
    return alert
