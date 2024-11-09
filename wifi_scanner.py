import tkinter as tk
from tkinter import messagebox
import sqlite3
import time
import threading
from pywifi import PyWiFi

# Initialize the database
def init_db():
    conn = sqlite3.connect("trusted_networks.db")
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS trusted_networks (
                        id INTEGER PRIMARY KEY,
                        ssid TEXT NOT NULL,
                        mac TEXT NOT NULL
                    )''')
    conn.commit()
    conn.close()

# Function to load trusted networks from the database
def load_trusted_networks():
    conn = sqlite3.connect("trusted_networks.db")
    cursor = conn.cursor()
    cursor.execute("SELECT ssid, mac FROM trusted_networks")
    trusted = cursor.fetchall()
    conn.close()
    return trusted

# Function to add a trusted network to the database
def add_trusted_network():
    ssid = ssid_entry.get()
    mac = mac_entry.get()
    
    if ssid and mac:
        conn = sqlite3.connect("trusted_networks.db")
        cursor = conn.cursor()
        cursor.execute("INSERT INTO trusted_networks (ssid, mac) VALUES (?, ?)", (ssid, mac))
        conn.commit()
        conn.close()
        messagebox.showinfo("Trusted Network Added", f"Added SSID: {ssid}, MAC: {mac} to trusted networks.")
        ssid_entry.delete(0, tk.END)
        mac_entry.delete(0, tk.END)
    else:
        messagebox.showwarning("Input Error", "Please enter both SSID and MAC address.")

# Initialize WiFi interface
wifi = PyWiFi()
iface = wifi.interfaces()[0]

# Flag to indicate scanning state
scanning = False

# Function to scan networks and compare with the trusted list
def scan_networks():
    if not scanning:
        return

    # Load the trusted networks from the database
    trusted_networks = load_trusted_networks()

    iface.scan()
    time.sleep(3)  # Wait for scan to complete
    scan_results = iface.scan_results()
    
    rogue_networks = []
    
    # Check each scanned network
    for network in scan_results:
        # If the network is not trusted, add it to rogue list
        is_trusted = any(
            network.ssid == trusted[0] and network.bssid == trusted[1]
            for trusted in trusted_networks
        )
        if not is_trusted:
            rogue_networks.append((network.ssid, network.bssid, network.signal))

    # Update the rogue networks list display
    update_rogue_list(rogue_networks)
    
    # Schedule the next scan in 5 seconds
    root.after(5000, scan_networks)

# Function to update rogue networks display
def update_rogue_list(rogue_networks):
    rogue_list.delete(0, tk.END)  # Clear current list display
    for ssid, bssid, signal in rogue_networks:
        rogue_list.insert(tk.END, f"SSID: {ssid}, BSSID: {bssid}, Signal: {signal}")

# Function to toggle scanning
def toggle_scanning():
    global scanning
    if not scanning:
        scanning = True
        start_stop_button.config(text="Stop Scanning")
        scan_networks()  # Start scanning
    else:
        scanning = False
        start_stop_button.config(text="Start Scanning")

# GUI setup
root = tk.Tk()
root.title("Wi-Fi Scanner")

# Labels and input fields for SSID and MAC
ssid_label = tk.Label(root, text="SSID:")
ssid_label.pack()
ssid_entry = tk.Entry(root)
ssid_entry.pack()

mac_label = tk.Label(root, text="MAC Address:")
mac_label.pack()
mac_entry = tk.Entry(root)
mac_entry.pack()

# Button to add a trusted network
add_button = tk.Button(root, text="Add Trusted Network", command=add_trusted_network)
add_button.pack()

# Start/Stop scan button
start_stop_button = tk.Button(root, text="Start Scanning", command=toggle_scanning)
start_stop_button.pack()

# Listbox to display rogue networks
rogue_label = tk.Label(root, text="Rogue Networks:")
rogue_label.pack()
rogue_list = tk.Listbox(root, width=50)
rogue_list.pack()

# Initialize the database
init_db()

# Run the GUI loop
root.mainloop()

