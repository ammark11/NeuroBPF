# evaluate_model.py

import pandas as pd
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import matplotlib.pyplot as plt
import seaborn as sns

# Load preprocessed data
data = pd.read_csv('../data/preprocessed_data.csv')

# Prepare features and labels
X = data.drop(['pid', 'label'], axis=1)
y = data['label']

# Split data (ensure the same split as during training)
_, X_test, _, y_test = train_test_split(X, y, test_size=0.3, stratify=y, random_state=42)

# Load the trained model
model = joblib.load('malware_detection_model.joblib')

# Predict
y_pred = model.predict(X_test)

# Evaluate
print("Classification Report:")
print(classification_report(y_test, y_pred))

# Confusion Matrix
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(6,4))
sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Normal', 'Malicious'], yticklabels=['Normal', 'Malicious'])
plt.xlabel('Predicted')
plt.ylabel('Actual')
plt.title('Confusion Matrix')
plt.savefig('confusion_matrix.png')
plt.show()
