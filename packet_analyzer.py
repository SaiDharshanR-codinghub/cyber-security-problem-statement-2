import tkinter as tk
from tkinter import messagebox, Toplevel
from scapy.all import sniff, IP, TCP, UDP, Raw
import threading
import time
import pandas as pd
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
import matplotlib.pyplot as plt
from PIL import Image, ImageTk
from collections import Counter
from datetime import datetime

# Global variables to handle sniffing state, packet storage, and stopping event
capturing = False
packets = []
stop_event = threading.Event()

# Function to process each captured packet and add to packets list
def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        packet_size = len(packet)
        protocol = 'Unknown'

        if TCP in packet:
            protocol = 'TCP'
        elif UDP in packet:
            protocol = 'UDP'
        elif Raw in packet:
            protocol = 'Raw'

        # Timestamp for the packet
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(packet.time))

        # Store packet details
        packets.append({
            'timestamp': timestamp,
            'src_ip': ip_src,
            'dst_ip': ip_dst,
            'protocol': protocol,
            'packet_size': packet_size
        })

        # Display the packet details in the appropriate listbox
        display_packet(protocol, f"{timestamp} - Src: {ip_src}, Dst: {ip_dst}, Size: {packet_size}")

def display_packet(protocol, packet_details):
    """Display packets in the correct listbox based on protocol."""
    if protocol == 'TCP':
        tcp_listbox.insert(tk.END, packet_details)
    elif protocol == 'UDP':
        udp_listbox.insert(tk.END, packet_details)
    else:
        raw_listbox.insert(tk.END, packet_details)

# Function to start packet capturing in a separate thread
def start_capture():
    global capturing
    if not capturing:
        capturing = True
        stop_event.clear()
        start_button.config(state=tk.DISABLED)
        stop_button.config(state=tk.NORMAL)

        # Start packet capture in a separate thread
        capture_thread = threading.Thread(target=capture_packets)
        capture_thread.daemon = True
        capture_thread.start()

# Function to stop packet capturing
def stop_capture():
    global capturing
    capturing = False
    stop_event.set()
    start_button.config(state=tk.NORMAL)
    stop_button.config(state=tk.DISABLED)

# Function to capture packets
def capture_packets():
    sniff(prn=process_packet, store=False, filter="ip", stop_filter=stop_filter)

def stop_filter(packet):
    """Stop filter based on stop_event."""
    return stop_event.is_set()

# K-means clustering and anomaly detection
def detect_anomalies():
    if not packets:
        messagebox.showinfo("Info", "No packets captured for analysis.")
        return

    # Create DataFrame for analysis
    df = pd.DataFrame(packets)

    # Encode protocol type and scale features
    df['protocol_encoded'] = df['protocol'].map({'TCP': 1, 'UDP': 2, 'Raw': 3})
    feature_data = df[['packet_size', 'protocol_encoded']]

    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(feature_data)

    # Perform K-means clustering
    kmeans = KMeans(n_clusters=2, random_state=0)
    clusters = kmeans.fit_predict(scaled_features)
    df['cluster'] = clusters

    # Calculate distance from cluster centroids
    distances = kmeans.transform(scaled_features)
    df['distance'] = distances.min(axis=1)
    
    # Threshold for anomalies (based on distance from cluster center)
    threshold = df['distance'].quantile(0.95)  # Top 5% as anomalies
    anomalies = df[df['distance'] > threshold]

    # Display anomalies in alert and highlight them in the listboxes
    if not anomalies.empty:
        for _, anomaly in anomalies.iterrows():
            alert_msg = f"Anomaly Detected!\nTime: {anomaly['timestamp']}, Src: {anomaly['src_ip']}, Dst: {anomaly['dst_ip']}, Size: {anomaly['packet_size']}"
            messagebox.showwarning("Anomaly Alert", alert_msg)
    else:
        messagebox.showinfo("Anomaly Detection", "No anomalies detected.")

# Visualization and reporting
def generate_report():
    if not packets:
        messagebox.showinfo("Info", "No data available for report generation.")
        return

    df = pd.DataFrame(packets)

    # Protocol distribution
    protocol_counts = df['protocol'].value_counts()

    # Plot Pie chart for protocol distribution
    fig, ax = plt.subplots(figsize=(6, 6))
    protocol_counts.plot(kind='pie', autopct='%1.1f%%', startangle=90, ax=ax)
    ax.set_title("Protocol Distribution")
    ax.set_ylabel('')  # Remove the y-label to make it cleaner

    # Save the pie chart to a temporary image file
    fig.savefig('protocol_pie_chart.png')

    # Scatter plot for K-means clustering
    fig2, ax2 = plt.subplots(figsize=(6, 6))
    ax2.scatter(df['packet_size'], df['protocol_encoded'], c=df['cluster'], cmap='viridis')
    ax2.set_title("K-means Clustering of Packets")
    ax2.set_xlabel("Packet Size")
    ax2.set_ylabel("Protocol Encoded")
    
    # Save the scatter plot to a temporary image file
    fig2.savefig('kmeans_scatter_plot.png')

    # Open a new window to show the visualizations
    report_window = Toplevel(root)
    report_window.title("Traffic Analysis Report")

    # Load and display the Pie chart
    pie_image = Image.open('protocol_pie_chart.png')
    pie_image = ImageTk.PhotoImage(pie_image)
    pie_label = tk.Label(report_window, image=pie_image)
    pie_label.image = pie_image
    pie_label.pack(pady=10)

    # Load and display the K-means Scatter plot
    scatter_image = Image.open('kmeans_scatter_plot.png')
    scatter_image = ImageTk.PhotoImage(scatter_image)
    scatter_label = tk.Label(report_window, image=scatter_image)
    scatter_label.image = scatter_image
    scatter_label.pack(pady=10)

# Set up the GUI window
root = tk.Tk()
root.title("Packet Capture and Analysis")

# Start and Stop buttons
start_button = tk.Button(root, text="Start Capture", command=start_capture)
start_button.pack(pady=5)

stop_button = tk.Button(root, text="Stop Capture", command=stop_capture, state=tk.DISABLED)
stop_button.pack(pady=5)

# Listboxes to display captured packets
tcp_label = tk.Label(root, text="TCP Packets")
tcp_label.pack()
tcp_listbox = tk.Listbox(root, width=80, height=10)
tcp_listbox.pack(pady=5)

udp_label = tk.Label(root, text="UDP Packets")
udp_label.pack()
udp_listbox = tk.Listbox(root, width=80, height=10)
udp_listbox.pack(pady=5)

raw_label = tk.Label(root, text="Raw Packets")
raw_label.pack()
raw_listbox = tk.Listbox(root, width=80, height=10)
raw_listbox.pack(pady=5)

# Analyze Button
analyze_button = tk.Button(root, text="Detect Anomalies", command=detect_anomalies)
analyze_button.pack(pady=5)

# Report Button
report_button = tk.Button(root, text="Generate Report", command=generate_report)
report_button.pack(pady=5)

# Run the Tkinter event loop
root.mainloop()