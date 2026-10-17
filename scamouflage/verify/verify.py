"""Role D owns this file. FAKE STATION: replace the body, keep the signature.

verify(record) -> {"status": "ok" | "fail" | "unknown_issuer", "algo": str}

Note: Static CT logs (Let's Encrypt Sycamore/Willow) send NO chain, so
record["chain_b64"] can be []. Return "unknown_issuer" unless you look the
issuer up yourself (cache issuers by name -> DER).
"""


def verify(record: dict) -> dict:
    return {"status": "ok", "algo": "fake"}
