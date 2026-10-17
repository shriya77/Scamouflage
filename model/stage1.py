"""
Scamouflage — model/stage1.py  (owner: Vaishnavi)       MODEL_SPEC §6

Stage 1: the name model. Gives each name a scam score from 0.0 to 1.0.
Loads data/models/stage1.joblib written by model/train_stage1.py.

If the model file doesn't exist yet, Stage1() raises FileNotFoundError; Engine.from_disk catches that
and runs without Stage 1 (everything gated scores 0.0 -> SAFE), so the pipeline never crashes.

Keep the class name and method signatures exactly as below — engine.py calls them.
"""
import os

import numpy as np

from . import features as F

NGRAM_PARAMS = {"analyzer": "char_wb", "ngram_range": (3, 5), "n_features": 2 ** 20,
                "alternate_sign": False, "norm": "l2", "lowercase": True}


def ngram_vectorizer(params=None):
    from sklearn.feature_extraction.text import HashingVectorizer
    return HashingVectorizer(**(params or NGRAM_PARAMS))   # stateless: same params -> same features


def _default_dir():
    return os.environ.get("SCAM_MODELS") or os.path.join(F.ROOT, "data", "models")


class Stage1:
    def __init__(self, model_dir=None):
        import joblib
        path = os.path.join(model_dir or _default_dir(), "stage1.joblib")
        if not os.path.exists(path):
            raise FileNotFoundError(f"{path} not found — run model/train_stage1.py first")
        m = joblib.load(path)
        if list(m["feature_names"]) != list(F.FEATURE_NAMES):
            raise ValueError("model was trained with different features — retrain with the current features.py")
        self.version = m["version"]
        self.vec = ngram_vectorizer(m["ngram_params"])
        self.clf_a, self.clf_b = m["clf_a"], m["clf_b"]
        self.iso_a, self.iso_b = m["iso_a"], m["iso_b"]

    def score(self, host: str) -> float:
        return self.score_many([host])[0]

    def score_many(self, hosts: list) -> list:
        if not hosts:
            return []
        hosts = [str(h).lower() for h in hosts]
        pa = self.iso_a.predict(self.clf_a.predict_proba(self.vec.transform(hosts))[:, 1])
        Xb = np.asarray([F.name_vector(h) for h in hosts], dtype=np.float32)
        pb = self.iso_b.predict(self.clf_b.predict_proba(Xb)[:, 1])
        return [float(x) for x in np.clip((pa + pb) / 2, 0.0, 1.0)]
