"""
Scamouflage — model/stage1.py  (owner: Vaishnavi)   *** STUB — replaced once the model is trained ***

Stage 1: the name model. Gives each name a scam score from 0.0 to 1.0. (MODEL_SPEC §6)

The stub scores everything 0.0, so the engine marks everything SAFE. That is on purpose: the
pipeline can be wired and tested end to end before the real model exists.

Keep the class name and method signatures exactly as below — engine.py calls them.
"""


class Stage1:
    version = "stub"

    def __init__(self, model_dir=None):
        self.model_dir = model_dir

    def score(self, host: str) -> float:
        return self.score_many([host])[0]

    def score_many(self, hosts: list) -> list:
        return [0.0] * len(hosts)
