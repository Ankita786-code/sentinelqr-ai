import pandas as pd
import joblib
import os
import sys

# Add project root to Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from models.feature_extractor import extract_features

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report

# ----------------------------
# Load Dataset
# ----------------------------

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATASET_PATH = os.path.join(BASE_DIR, "dataset", "urls.csv")

data = pd.read_csv(DATASET_PATH)

# ----------------------------
# Feature Extraction
# ----------------------------

X = [extract_features(url) for url in data["url"]]
y = data["label"]

# ----------------------------
# Train/Test Split
# ----------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# ----------------------------
# Train Model
# ----------------------------

model = RandomForestClassifier(
    n_estimators=100,
    random_state=42
)

model.fit(X_train, y_train)

# ----------------------------
# Evaluation
# ----------------------------

pred = model.predict(X_test)

print("Accuracy:", accuracy_score(y_test, pred))
print(classification_report(y_test, pred))

# ----------------------------
# Save Model
# ----------------------------

MODEL_PATH = os.path.join(BASE_DIR, "model.pkl")

joblib.dump(model, MODEL_PATH)

print("✅ Model Saved Successfully")