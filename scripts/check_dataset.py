import pandas as pd
import joblib
import os
import sys

from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
from xgboost import XGBClassifier

print("Loading dataset...")

# Resolve paths
current_dir = os.path.dirname(os.path.abspath(__file__))
if os.path.basename(current_dir) == "scripts":
    project_root = os.path.abspath(os.path.join(current_dir, ".."))
else:
    project_root = os.path.abspath(current_dir)

dataset_path = os.path.join(project_root, "data", "drebin-215-dataset-5560malware.csv")
if not os.path.exists(dataset_path):
    dataset_path = os.path.join(project_root, "drebin-215-dataset-5560malware.csv")

if not os.path.exists(dataset_path):
    print(f"Error: Dataset not found at {dataset_path}")
    sys.exit(1)

# Load dataset
df = pd.read_csv(dataset_path, low_memory=False)

print("Dataset Shape:", df.shape)

# Convert labels
df["class"] = df["class"].map({
    "S": 1,   # Malware
    "B": 0    # Benign
})

# Features and target
X = df.drop("class", axis=1)
y = df["class"]

# Convert all columns to numeric
X = X.apply(pd.to_numeric, errors="coerce")

# Replace missing values with 0
X = X.fillna(0)

# Remove any remaining object columns
object_cols = X.select_dtypes(include=["object"]).columns.tolist()

if object_cols:
    print("\nRemoving object columns:")
    print(object_cols)
    X = X.drop(columns=object_cols)

print("\nFeature Shape:", X.shape)

print("\nRemaining Object Columns:")
print(X.select_dtypes(include=["object"]).columns.tolist())

# Train Test Split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("\nTraining Samples:", len(X_train))
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

# Save model
models_dir = os.path.join(project_root, "models")
os.makedirs(models_dir, exist_ok=True)
model_path = os.path.join(models_dir, "malware_model.pkl")
joblib.dump(model, model_path)
print(f"\nModel saved as {model_path}")