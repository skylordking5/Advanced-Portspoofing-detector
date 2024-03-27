import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense
from scapy.all import sniff, TCP, IP
import threading

# Define LSTM-based neural network architecture
def create_model(input_shape):
    model = Sequential([
        LSTM(64, input_shape=input_shape, return_sequences=True),
        LSTM(64, return_sequences=False),
        Dense(1, activation='sigmoid')
    ])
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
    return model

# Feature extraction and data preprocessing
def extract_features(packet):
    if packet.haslayer(IP) and packet.haslayer(TCP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
        payload_size = len(packet[TCP].payload)
        return [src_ip, dst_ip, src_port, dst_port, payload_size]

# Real-time port spoofing detection using LSTM model
def detect_port_spoofing(packet):
    features = extract_features(packet)
    if features:
        features = np.array(features).reshape(1, 1, len(features))
        prediction = model.predict(features)
        if prediction >= 0.5:
            print("Port spoofing detected!")

# Packet sniffing thread
def start_sniffing(interface, packet_limit):
    sniff(prn=detect_port_spoofing, iface=interface, count=packet_limit)

# Main function
if __name__ == "__main__":
    interface = "eth0"
    packet_limit = 1000

    model = create_model(input_shape=(1, 5))

    sniff_thread = threading.Thread(target=start_sniffing, args=(interface, packet_limit))
    sniff_thread.start()
