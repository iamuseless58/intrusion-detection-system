AI-Enabled IoT Intrusion Detection System (IDS)

An intelligent network security solution designed for IoT environments. This project uses Machine Learning (Random Forest) to monitor network traffic and detect potential cyber threats in real-time.

* Project Structure

Based on the current repository, here is the breakdown of the files:

* 1_train_model.py: Python script to train the Random Forest classifier using historical IoT traffic data.
* 2_edge_ids_gui.py: The main application file. It features a Tkinter-based GUI for real-time traffic sniffing and anomaly detection.
* attack_generator.py: A utility script used to simulate network attacks (like DoS or Scanning) for testing the system.
* create_sample_data.py: Generates or pre-processes the initial dataset for model training.
* ids_rf_model.joblib`: The saved pre-trained Random Forest model.
* le_proto.joblib / le_service.joblib: Label Encoders for categorical network features (Protocol and Service).
* scaler.joblib: The saved Scaler object to ensure real-time data matches the training data distribution.
* sampled_iot_data.csv: The dataset used for training and validation.

 Features

* Real-time Sniffing: Uses 'Scapy' to capture live network packets.
* Machine Learning Inference: Predicts whether a packet is 'Normal' or an 'Attack' using the 'joblib' integrated model.
* Graphical Dashboard: Visual interface to view live logs, packet counts, and threat alerts.
* Edge Ready: Optimized to run on edge gateways or local workstations monitoring IoT traffic.

Setup & Installation

 1. Prerequisites
Ensure you have Python 3.x installed along with the following libraries:

pip install scapy pandas scikit-learn joblib
if your running this project in windows make sure that you have to install NCAP
