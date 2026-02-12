import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib

# Load dataset
df = pd.read_csv("phishing_dataset.csv")

# Normalize columns
df.columns = [c.strip() for c in df.columns]
df.columns = [c if c != 'ClassLabel' else 'label' for c in df.columns]
df.columns = [c if c != 'URL' else 'url' for c in df.columns]

# Drop rows with missing label
df = df.dropna(subset=["label"])

# Fill missing features with 0
feature_cols = [c for c in df.columns if c not in ["url", "label"]]
df[feature_cols] = df[feature_cols].fillna(0)

# Features and target
X = df[feature_cols]
y = df["label"]

# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train RandomForest
clf = RandomForestClassifier(n_estimators=200, random_state=42)
clf.fit(X_train, y_train)

# Save model
joblib.dump(clf, "phishing_model.pkl")
print("ML model saved as phishing_model.pkl")

