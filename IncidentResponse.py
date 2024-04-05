import socket
import smtplib
from collections import deque
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from scapy.all import sniff, IP, TCP, ARP, getmacbyip, ICMP
import threading
import time

# Currently looks for DDoS, irregular activity from an IP
# Maybe examine payloads, protocols, DNS tunneling.

def send_email(message):
    msg = MIMEMultipart()
    msg['From'] = "coleturneryoung2@gmail.com"
    msg['To'] = "coleturneryoung@gmail.com"
    msg['Subject'] = "Warning Irregular Activity"
    
    msg.attach(MIMEText(message, 'plain'))
    
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login("coleturneryoung2@gmail.com", "oxtu hwru wlhd uqvx")
        text = msg.as_string()
        server.sendmail("coleturneryoung2@gmail.com", "coleturneryoung@gmail.com", text)
        
        print("Email sent successfully!")
    except Exception as e:
        print("Email could not be sent:", str(e))
    finally:
        server.quit()

# Function to check for suspicious activity
def check_suspicious(ip):
    if ip in connection_attempts:
        if len(connection_attempts[ip]) > 1:
            # Calculate time difference between first and last connection attempt
            time_diff = connection_attempts[ip][-1] - connection_attempts[ip][0]
            # Threshold for detecting suspicious activity
            if time_diff < 10:
                print("Suspicious activity detected")
                send_email(f"Suspicious activity detected from {ip}:{len(connection_attempts[ip])} connection attempts in {time_diff} seconds.", time.time())

                
# Function to check for possible ARP poisoning
def analyze_arp_packets(packet):
    if ARP in packet:
        arp_packet = packet[ARP]
        if arp_packet.op == 2:
            sender_ip = arp_packet.psrc
            sender_mac = arp_packet.hwsrc
            actual_mac = getmacbyip(sender_ip)
            if actual_mac is not None and actual_mac != sender_mac:
                print("Possible ARP poisoning detected")
                send_email("Possible ARP poisoning detected from IP", sender_ip)
                
# Function to check for possible ICMP ping flood attack
def detect_ping_flood(packet):
    global echo_requests
    # ICMP type 8 is echo request
    if ICMP in packet and packet[ICMP].type == 8:
        echo_requests.append(time.time())
        
        if len(echo_requests) >= 10:
            time_difference = echo_requests[-1] - echo_requests[0]
            if time_difference <= 10:
                print("Possible ping flood detected")
                send_email(f"Possible ping flood detected from source: {packet[IP].src}")

# Function to check for possible UDP DDoS attack
def check_ddos():
    global packet_count, last_check_time
    while True:
        packet_count += 1
        current_time = time.time()
        if current_time - last_check_time >= 30:
            if packet_count > 3:
                print("Possible DDoS detected")
                send_email("Network traffic spike detected, sending email")
            packet_count = 0
            last_check_time = current_time

# Function to check for possible TCP SYN flooding attack
def detect_syn_flood(packet):
    global syn_packets
    if TCP in packet and packet[TCP].flags & 2:  # Check if it's a SYN packet
        src_ip = packet[IP].src
        if src_ip not in syn_packets:
            syn_packets[src_ip] = 1
        else:
            syn_packets[src_ip] += 1
        if syn_packets[src_ip] > 20:  # Modify threshold as needed
            print("Possible TCP SYN flooding attack detected")
            send_email(f"Possible TCP SYN flooding attack detected from source: {src_ip}")

# Callback function to handle received packets
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        if TCP in packet:
            dst_port = packet[TCP].dport
            # Track connection attempts per IP
            if src_ip not in connection_attempts:
                connection_attempts[src_ip] = []
            connection_attempts[src_ip].append(time.time())
            
            # Checks for irregular activity from IP (Attempting to reach many sockets in short amount of time)
            check_suspicious(src_ip)

# Initialize global variables
packet_count = 0
connection_attempts = {}
last_check_time = time.time()
ping_time = 10
syn_packets = {}
echo_requests = []

# Create threads for each function
threading.Thread(target=sniff, kwargs={'prn': packet_callback, 'store': False}).start()
threading.Thread(target=sniff, kwargs={'filter': "icmp", 'prn': detect_ping_flood}).start()
threading.Thread(target=sniff, kwargs={'filter': "tcp", 'prn': detect_syn_flood}).start()
threading.Thread(target=sniff, kwargs={'filter': "arp", 'prn': analyze_arp_packets}).start()
threading.Thread(target=check_ddos).start()
