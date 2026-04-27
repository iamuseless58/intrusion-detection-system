import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler, LabelEncoder
from sklearn.metrics import classification_report
import joblib

# --- Configuration ---
DATASET_PATH = 'sampled_iot_data.csv'  # Ensure this file exists
MODEL_FILE = 'ids_rf_model.joblib'
SCALER_FILE = 'scaler.joblib'
FEATURES = [
    'src_bytes', 'dst_bytes', 'duration', 'service', 'protocol_type', 
    'serror_rate', 'srv_serror_rate', 'logged_in', 'count' # Features MUST match CSV headers
]

# --- 1. Load and Preprocess Data ---
print("Starting Model Training...")
try:
    df = pd.read_csv(DATASET_PATH)
    print(f"Dataset loaded: {df.shape[0]} rows, {df.shape[1]} columns.")
except FileNotFoundError:
    print(f"Error: Dataset not found at {DATASET_PATH}. Please check the file path.")
    exit()

# Simplify the 'label' column to a binary classification: 0 (Normal) or 1 (Attack)
df['binary_label'] = df['label'].apply(lambda x: 0 if x == 'Normal' else 1)

# Handle categorical features
le_proto = LabelEncoder()
le_service = LabelEncoder()

# Fit and transform 'protocol_type'
df['protocol_type'] = le_proto.fit_transform(df['protocol_type'].astype(str))
# Fit and transform 'service'
df['service'] = le_service.fit_transform(df['service'].astype(str))


X = df[FEATURES].copy()
y = df['binary_label']

# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

# Scale numerical features (Mandatory for consistent real-time feature extraction)
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)

# --- 2. Train the Random Forest Model (Lightweight for Edge) ---
print("Training Random Forest Classifier (n_estimators=50, max_depth=10)...")
rf_model = RandomForestClassifier(n_estimators=50, max_depth=10, random_state=42, n_jobs=-1)
rf_model.fit(X_train_scaled, y_train)

# --- 3. Evaluate and Save ---
print("Evaluating model...")
y_pred = rf_model.predict(X_test_scaled)
print(classification_report(y_test, y_pred, target_names=['Normal', 'Attack']))

print(f"\nSaving model to {MODEL_FILE}, scaler to {SCALER_FILE}...")
joblib.dump(rf_model, MODEL_FILE)
joblib.dump(scaler, SCALER_FILE)
# Also save the encoders for consistent inference on the edge
joblib.dump(le_proto, 'le_proto.joblib')
joblib.dump(le_service, 'le_service.joblib')

print("Training complete. Files saved for edge deployment.")