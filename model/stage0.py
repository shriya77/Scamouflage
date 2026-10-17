"""
Scamouflage — model/stage0.py  (owner: Shriya)   *** STUB — replace with the real version ***

Stage 0: is this exact name already on our known-scam list? (MODEL_SPEC §4.3, §5)

Real version must:
  - load ALL hosts from the `labels` table of labels.db (shared path) into an in-memory set
  - refresh() every 15 min: load only rows with last_seen > last refresh, return how many were added
  - check(host): exact host, or its registered domain if that domain itself is listed
  - open SQLite in WAL mode with timeout=30; never query SQLite per certificate

Keep the class name and method signatures exactly as below — engine.py calls them.
"""


class KnownList:
    def __init__(self, db_path=None):
        self.db_path = db_path
        self.hosts = set()

    def refresh(self) -> int:
        return 0

    def check(self, host: str):
        """Return {"brand": str|None, "category": str, "feed": str} if known, else None."""
        return None
