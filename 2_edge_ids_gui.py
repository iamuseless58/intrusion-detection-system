import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from scapy.all import sniff, IP, TCP, UDP, Raw
import pandas as pd
import numpy as np
import joblib
import threading
import time
import queue
import sys

# --- Configuration ---
MODEL_FILE = 'ids_rf_model.joblib'
SCALER_FILE = 'scaler.joblib'
LE_PROTO_FILE = 'le_proto.joblib'
LE_SERVICE_FILE = 'le_service.joblib'

INTERFACE = 'Wi-Fi'  # !!! CHANGE THIS to your actual interface (e.g., 'wlan0', 'eth0') !!!
FEATURES = [
    'src_bytes', 'dst_bytes', 'duration', 'service', 'protocol_type', 
    'serror_rate', 'srv_serror_rate', 'logged_in', 'count'
]
PROTOCOL_MAP = {1: 'icmp', 6: 'tcp', 17: 'udp'} # Protocol number mapping

# --- 1. Edge Model Loading and Feature Mapping ---
try:
    ids_model = joblib.load(MODEL_FILE)
    scaler = joblib.load(SCALER_FILE)
    le_proto = joblib.load(LE_PROTO_FILE)
    le_service = joblib.load(LE_SERVICE_FILE)
    print("ML Model, Scaler, and Encoders loaded successfully.")
except FileNotFoundError as e:
    print(f"CRITICAL: Required model file not found: {e}. Run '1_train_model.py' first.")
    sys.exit(1)


def extract_features_from_packet(pkt):
    """Extracts required features from a single Scapy packet."""
    feature_vector = {}
    
    # 1. Byte Counts (approximate)
    feature_vector['src_bytes'] = pkt.len
    feature_vector['dst_bytes'] = pkt.len # Simplification for demo
    
    # 2. Duration (placeholder for demo - should be flow-based)
    feature_vector['duration'] = 0.0 
    
    # 3. Protocol Type
    proto_name = ""
    if IP in pkt:
        proto_num = pkt[IP].proto
        proto_name = PROTOCOL_MAP.get(proto_num, 'other')
    else:
        proto_name = 'other' # Non-IP packets

    # 4. Service (Simplistic mapping for demo based on common ports)
    service_name = 'other'
    if TCP in pkt:
        dport = pkt[TCP].dport
        if dport == 80: service_name = 'http'
        elif dport == 21: service_name = 'ftp'
        elif dport == 23: service_name = 'telnet'
    elif UDP in pkt:
        dport = pkt[UDP].dport
        if dport == 53: service_name = 'dns'
        
    # 5. Error/Status indicators (Simplistic placeholder)
    feature_vector['serror_rate'] = 0.0
    feature_vector['srv_serror_rate'] = 0.0
    feature_vector['logged_in'] = 0
    feature_vector['count'] = 1 

    # Apply Encoders (using saved objects)
    try:
        encoded_proto = le_proto.transform([proto_name])[0]
    except ValueError:
        # Handle unseen category: assign a default (0) or the category's last known index
        encoded_proto = 0
        
    try:
        encoded_service = le_service.transform([service_name])[0]
    except ValueError:
        encoded_service = 0

    feature_vector['protocol_type'] = encoded_proto
    feature_vector['service'] = encoded_service
    
    # Create DataFrame for scaling (ensures feature order)
    data_row = pd.DataFrame([feature_vector], columns=FEATURES)

    # Scale numerical features (Edge Computation)
    scaled_data = scaler.transform(data_row)
    return scaled_data.flatten()


# --- 2. Real-Time Detection Core Logic (Edge Computation) ---
def packet_callback(pkt, ids_model, log_queue):
    # Filter for IP packets to ensure feature extraction works
    if not IP in pkt:
        return

    try:
        # Step 1: Feature Extraction
        features_array = extract_features_from_packet(pkt)
        
        # Step 2: Edge Inference (Prediction)
        prediction = ids_model.predict([features_array])[0]
        
        # Step 3: Result & Logging
        label = "ATTACK detected! 🚨" if prediction == 1 else "Normal Traffic"
        log_message = f"[{time.strftime('%H:%M:%S')}] Src: {pkt[IP].src} | Dst: {pkt[IP].dst} | Proto: {PROTOCOL_MAP.get(pkt[IP].proto, 'Other')} | Result: {label}"
        
        # Send result to the GUI thread
        log_queue.put((log_message, prediction))
        
    except Exception as e:
        # This catches errors during feature extraction or model inference
        log_queue.put((f"[{time.strftime('%H:%M:%S')}] Internal Processing Error: {e}", -1))


def start_sniffing(ids_model, log_queue, stop_event, interface):
    print(f"Sniffing thread started on interface {interface}...")
    # The 'prn' calls the packet_callback for every packet
    try:
        # Filter="ip" ensures we only process IP packets
        sniff(iface=interface, prn=lambda pkt: packet_callback(pkt, ids_model, log_queue), 
              store=0, stop_filter=lambda x: stop_event.is_set(), filter="ip")
    except OSError as e:
        log_queue.put((f"CRITICAL ERROR: Packet sniffing failed. Run with sudo/admin or check interface name '{interface}'. ({e})", -1))
    except Exception as e:
        log_queue.put((f"Sniffing failed: {e}", -1))


# --- 3. Tkinter GUI Implementation ---
class IDS_GUI:
    def __init__(self, master):
        self.master = master
        master.title("AI-Enabled IoT IDS Edge Monitor")
        master.geometry("800x600")

        self.sniff_thread = None
        self.stop_event = threading.Event()
        self.log_queue = queue.Queue()
        self.attack_count = 0
        self.normal_count = 0
        self.running = False

        # --- GUI Elements ---
        
        # Status Frame
        status_frame = tk.Frame(master, bd=2, relief=tk.GROOVE)
        status_frame.pack(fill='x', padx=10, pady=5)
        
        self.status_label = tk.Label(status_frame, text="STATUS: STOPPED", fg="red", font=('Arial', 12, 'bold'))
        self.status_label.pack(side=tk.LEFT, padx=10, pady=5)

        # Counter Labels
        self.count_label = tk.Label(status_frame, text="Normal: 0 | Attack: 0", font=('Arial', 12))
        self.count_label.pack(side=tk.RIGHT, padx=10, pady=5)
        
        # Controls
        control_frame = tk.Frame(master)
        control_frame.pack(fill='x', padx=10, pady=5)
        
        self.start_button = tk.Button(control_frame, text="Start IDS", command=self.start_ids, bg='green', fg='white')
        self.start_button.pack(side=tk.LEFT, padx=5)
        
        self.stop_button = tk.Button(control_frame, text="Stop IDS", command=self.stop_ids, bg='red', fg='white', state=tk.DISABLED)
        self.stop_button.pack(side=tk.LEFT, padx=5)

        # Log Text Area
        log_label = tk.Label(master, text="Real-Time Detection Log (Interface: " + INTERFACE + "):")
        log_label.pack(anchor='w', padx=10)
        self.log_text = ScrolledText(master, height=30, state=tk.DISABLED, font=('Consolas', 10))
        self.log_text.pack(fill='both', expand=True, padx=10, pady=5)
        
        # Start the queue monitor
        self.master.after(100, self.process_queue)

    def start_ids(self):
        if not self.running:
            self.stop_event.clear()
            self.sniff_thread = threading.Thread(
                target=start_sniffing, 
                args=(ids_model, self.log_queue, self.stop_event, INTERFACE)
            )
            self.sniff_thread.daemon = True
            self.sniff_thread.start()
            
            self.running = True
            self.status_label.config(text="STATUS: RUNNING", fg="green")
            self.start_button.config(state=tk.DISABLED)
            self.stop_button.config(state=tk.NORMAL)
            self.log_to_gui(f"IDS Started on {INTERFACE}. Monitoring...", "normal")

    def stop_ids(self):
        if self.running:
            self.stop_event.set()
            if self.sniff_thread:
                # Wait a bit for the sniffing thread to close gracefully
                self.sniff_thread.join(timeout=2) 
            self.running = False
            self.status_label.config(text="STATUS: STOPPED", fg="red")
            self.start_button.config(state=tk.NORMAL)
            self.stop_button.config(state=tk.DISABLED)
            self.log_to_gui("IDS Stopped.", "normal")

    def process_queue(self):
        # Process items from the detection thread's queue (thread-safe update)
        while not self.log_queue.empty():
            log_message, prediction = self.log_queue.get()
            
            if prediction == 1:
                self.attack_count += 1
                self.log_to_gui(log_message, "attack")
            elif prediction == 0:
                self.normal_count += 1
                self.log_to_gui(log_message, "normal")
            else: # Error or other
                self.log_to_gui(log_message, "error")
                
            self.update_counts()

        self.master.after(100, self.process_queue) # Check the queue again after 100ms

    def log_to_gui(self, message, type="normal"):
        self.log_text.config(state=tk.NORMAL)
        self.log_text.insert(tk.END, message + "\n")
        
        # Simple color tagging for logs
        if type == "attack":
            self.log_text.tag_config('attack', foreground='#ff4500', font=('Consolas', 10, 'bold')) # Orange-Red
            self.log_text.tag_add('attack', 'end-2l', 'end-1c')
        elif type == "error":
            self.log_text.tag_config('error', foreground='orange')
            self.log_text.tag_add('error', 'end-2l', 'end-1c')
            
        self.log_text.see(tk.END)
        self.log_text.config(state=tk.DISABLED)
        
    def update_counts(self):
        self.count_label.config(text=f"Normal: {self.normal_count} | Attack: {self.attack_count}")
        
    def on_closing(self):
        self.log_to_gui("Shutting down IDS and closing GUI...", "normal")
        self.stop_ids()
        self.master.destroy()

# --- Main GUI Loop ---
if __name__ == "__main__":
    root = tk.Tk()
    app = IDS_GUI(root)
    # Ensure a clean shutdown when closing the window
    root.protocol("WM_DELETE_WINDOW", app.on_closing) 
    root.mainloop()