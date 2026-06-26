import os
import joblib

from models.feature_extractor import extract_features

# ----------------------------
# Load Model
# ----------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")

model = joblib.load(MODEL_PATH)

# ----------------------------
# Prediction Function
# ----------------------------

def predict_url(url):

    features = extract_features(url)

    prediction = model.predict([features])[0]

    probability = model.predict_proba([features])[0]

    confidence = round(max(probability) * 100, 2)

    return prediction, confidence