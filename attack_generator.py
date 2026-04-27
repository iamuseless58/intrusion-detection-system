from scapy.all import IP, TCP, send
import sys

# REPLACE 'TARGET_IP' with a device's IP on your network (e.g., your own machine's IP)
TARGET_IP = "192.168.31.195" # Use the IP from your Wi-Fi adapter

# WARNING: Running this might trigger firewall warnings.
print(f"Starting SYN scan on {TARGET_IP}...")
for port in range(1, 999): # Scan the first 100 ports
    # Craft the packet: IP layer, TCP layer with SYN flag
    packet = IP(dst=TARGET_IP)/TCP(dport=port, flags="S")
    send(packet, verbose=0)
    sys.stdout.write(f"\rScanning port: {port}")

print("\nScan complete. Check IDS log.")