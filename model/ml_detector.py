import joblib
import pandas as pd
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "phishing_model.pkl"

model = joblib.load(MODEL_PATH)

columns = [
    "url_length",
    "valid_url",
    "at_symbol",
    "sensitive_words_count",
    "path_length",
    "isHttps",
    "nb_dots",
    "nb_hyphens",
    "nb_and",
    "nb_or",
    "nb_www",
    "nb_com",
    "nb_underscore"
]

def ml_predict(features):
    df = pd.DataFrame([features], columns=columns)

    prediction = model.predict(df)[0]

    if hasattr(model, "predict_proba"):
        probability = model.predict_proba(df)[0][1]
        risk_score = int(probability * 100)
    else:
        risk_score = 90 if prediction == 1 else 10

    return prediction, risk_score


def predict_url(features):
    return ml_predict(features)