import socket
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from scapy.all import sniff, IP, TCP
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
            if time_diff < 10:  # Adjust the time threshold as needed
                message = f"Suspicious activity detected from {ip}: {len(connection_attempts[ip])} connection attempts in {time_diff} seconds."
                send_email(message)

# Function to check for possible DDoS attack
def check_ddos():
    global packet_count, last_check_time
    packet_count += 1
    current_time = time.time()
    if current_time - last_check_time >= 30:
        if packet_count > 17000:
            send_email("Network traffic spike detected, sending email")
        packet_count = 0
        last_check_time = current_time

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
    
    # Checks for possible DDoS attacks
    check_ddos()

packet_count = 0
connection_attempts = {}
last_check_time = time.time()

sniff(prn=packet_callback, store=False)
