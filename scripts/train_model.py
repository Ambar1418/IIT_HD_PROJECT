import pandas as pd
import joblib
import os
import json

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier

print("Loading dataset...")

# Resolve paths
current_dir = os.path.dirname(os.path.abspath(__file__))
# Check if running inside scripts/ directory
if os.path.basename(current_dir) == "scripts":
    project_root = os.path.abspath(os.path.join(current_dir, ".."))
else:
    project_root = os.path.abspath(current_dir)

dataset_path = os.path.join(project_root, "data", "drebin-215-dataset-5560malware.csv")
if not os.path.exists(dataset_path):
    dataset_path = os.path.join(project_root, "drebin-215-dataset-5560malware.csv")

if not os.path.exists(dataset_path):
    print(f"Error: Dataset not found at {dataset_path}")
    import sys
    sys.exit(1)

# Load dataset
df = pd.read_csv(dataset_path, low_memory=False)

print("Dataset Shape:", df.shape)

# Replace problematic values
df = df.replace("?", 0)

# Convert labels
df["class"] = df["class"].map({
    "S": 1,  # Malware
    "B": 0   # Benign
})

# Features and target
X = df.drop("class", axis=1)
y = df["class"]

# Convert all features to numeric
X = X.apply(pd.to_numeric, errors="coerce")

# Fill missing values
X = X.fillna(0)

# Check for remaining object columns
object_cols = X.select_dtypes(include=["object"]).columns.tolist()

print("\nObject Columns:")
print(object_cols)

# Drop any remaining object columns
if len(object_cols) > 0:
    X = X.drop(columns=object_cols)

print("\nFinal Feature Shape:", X.shape)

# Train/Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training Samples:", len(X_train))
print("Testing Samples:", len(X_test))

# XGBoost Model
model = XGBClassifier(
    n_estimators=200,
    max_depth=8,
    learning_rate=0.1,
    random_state=42,
    eval_metric="logloss"
)

print("\nTraining model...")
model.fit(X_train, y_train)

print("\nMaking predictions...")
y_pred = model.predict(X_test)

# Accuracy
acc = accuracy_score(y_test, y_pred)

print("\n==============================")
print("Accuracy:", round(acc * 100, 2), "%")
print("==============================")

print("\nClassification Report:")
print(classification_report(y_test, y_pred))

# Save model and features dynamically
models_dir = os.path.join(project_root, "models")
os.makedirs(models_dir, exist_ok=True)
model_path = os.path.join(models_dir, "malware_model.pkl")
joblib.dump(model, model_path)
print(f"\nModel saved as {model_path}")

# Also save model to root fallback for backward compatibility
root_model_path = os.path.join(project_root, "malware_model.pkl")
joblib.dump(model, root_model_path)

# Save features
data_dir = os.path.join(project_root, "data")
os.makedirs(data_dir, exist_ok=True)
features_path = os.path.join(data_dir, "drebin_features.json")
with open(features_path, "w") as f:
    json.dump(list(X.columns), f, indent=2)
print(f"Features list saved as {features_path}")