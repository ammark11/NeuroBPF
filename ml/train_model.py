# train_model.py

import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
import joblib
import os

# Load preprocessed data
data = pd.read_csv('../data/preprocessed_data.csv')

# Prepare features and labels
X = data.drop(['pid', 'label'], axis=1)
y = data['label']

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)

# Initialize and train model
model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save the model
joblib.dump(model, 'malware_detection_model.joblib')

print("Model training completed and saved.")
