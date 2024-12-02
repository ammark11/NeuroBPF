# predict.py

import pandas as pd
import joblib

# Load new data
# For this example, we'll use the test data as new data
new_data = pd.read_csv('../data/preprocessed_data.csv')
X_new = new_data.drop(['pid', 'label'], axis=1)

# Load the trained model
model = joblib.load('malware_detection_model.joblib')

# Predict
predictions = model.predict(X_new)

# Add predictions to data
new_data['prediction'] = predictions

# Save predictions
new_data.to_csv('../data/predictions.csv', index=False)

print("Predictions saved to '../data/predictions.csv'")
