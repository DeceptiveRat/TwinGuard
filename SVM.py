import numpy as np
import pandas as pd
from sklearn.svm import SVC
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import json

def predict_live_traffic(model, scaler, new_data_point):
	scaled_point = scaler.transform([new_data_point])
	prediction = model.predict(scaled_point)
	probability = model.predict_proba(scaled_point)[0][1]
	is_attack = prediction[0] == 1
	return is_attack, probability

parsed_data=[]
number_of_data=0

with open("packet_data.log", "r") as file:
	raw_text = file.read()
	fixed_text = raw_text.replace('}{', '}\n{')
	for line in fixed_text.split('\n'):
		number_of_data+=1
		if line.strip():
			parsed_data.append(json.loads(line))

print(f"Dataset size: {number_of_data}")

df = pd.DataFrame(parsed_data)
# UDP RTT to -1.0
df['RTT'] = df['RTT'].fillna(-1.0)
# boolean to int
df['new_BSSID'] = df['new_BSSID'].astype(int)
# UDP and TCP to int 
protocol_map = {'UDP': 0, 'TCP': 1}
df['Protocol'] = df['Protocol'].map(protocol_map)

# split label 
X = df.drop('is_attack', axis=1)
y = df['is_attack']

# create training and testing datasets
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.3, random_state=42)

# scale data
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

print("Training the SVM model...")
svm_model = SVC(kernel='linear', C=1.0, probability=True)
svm_model.fit(X_train_scaled, y_train)

print("Evaluating model performance on test data...")
y_pred = svm_model.predict(X_test_scaled)

print("\n--- Confusion Matrix ---")
print(confusion_matrix(y_test, y_pred))

print("\n--- Classification Report ---")
print(classification_report(y_test, y_pred, target_names=['Normal', 'Evil Twin']))

