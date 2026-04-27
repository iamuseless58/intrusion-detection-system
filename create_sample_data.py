import pandas as pd
import numpy as np

# --- Configuration ---
N_ROWS = 10000  # Total number of rows to generate
NORMAL_RATIO = 0.60 # 60% Normal Traffic
ATTACK_RATIO = 0.40 # 40% Attack Traffic

FEATURES = [
    'src_bytes', 'dst_bytes', 'duration', 'service', 'protocol_type', 
    'serror_rate', 'srv_serror_rate', 'logged_in', 'count', 'label'
]

# --- 1. Define Normal Traffic Patterns (60% of data) ---
n_normal = int(N_ROWS * NORMAL_RATIO)
normal_data = pd.DataFrame({
    # Benign data tends to be smaller and last longer
    'src_bytes': np.random.randint(50, 500, n_normal),
    'dst_bytes': np.random.randint(100, 1000, n_normal),
    'duration': np.random.uniform(0.5, 5.0, n_normal).round(2),
    # Common services
    'service': np.random.choice(['http', 'ftp', 'dns', 'other'], n_normal, p=[0.4, 0.2, 0.2, 0.2]),
    # Common protocols
    'protocol_type': np.random.choice(['tcp', 'udp'], n_normal, p=[0.7, 0.3]),
    # Low error rate
    'serror_rate': np.random.uniform(0.0, 0.1, n_normal).round(2),
    'srv_serror_rate': np.random.uniform(0.0, 0.1, n_normal).round(2),
    # Logged in for many services
    'logged_in': np.random.choice([0, 1], n_normal, p=[0.3, 0.7]),
    'count': np.random.randint(1, 50, n_normal),
    'label': 'Normal'
})

# --- 2. Define Attack Traffic Patterns (40% of data) ---
n_attack = int(N_ROWS * ATTACK_RATIO)
attack_data = pd.DataFrame({
    # Attacks can be very high volume (DDoS) or low volume (Probe)
    'src_bytes': np.random.randint(10, 10000, n_attack),
    'dst_bytes': np.random.randint(10, 5000, n_attack),
    'duration': np.random.uniform(0.01, 1.0, n_attack).round(2),
    # Diverse services, often ICMP/other ports
    'service': np.random.choice(['http', 'ssh', 'other', 'ftp_control'], n_attack, p=[0.3, 0.3, 0.3, 0.1]),
    # Common attack protocols
    'protocol_type': np.random.choice(['tcp', 'udp', 'icmp'], n_attack, p=[0.5, 0.3, 0.2]),
    # High error rate (for SYN floods/denial)
    'serror_rate': np.random.uniform(0.5, 1.0, n_attack).round(2),
    'srv_serror_rate': np.random.uniform(0.5, 1.0, n_attack).round(2),
    # Not logged in
    'logged_in': 0,
    # High count in short duration
    'count': np.random.randint(100, 500, n_attack),
    'label': 'Attack'
})

# --- 3. Combine and Save ---
final_df = pd.concat([normal_data, attack_data]).sample(frac=1).reset_index(drop=True)
final_df = final_df[FEATURES] # Re-order columns just in case

# Save to the required CSV file
output_file = 'sampled_iot_data.csv'
final_df.to_csv(output_file, index=False)

print(f"Successfully generated {final_df.shape[0]} rows of mixed data to {output_file}.")
print(f"Normal samples: {n_normal} | Attack samples: {n_attack}")
print("\nNOW RERUN '1_train_model.py'!")