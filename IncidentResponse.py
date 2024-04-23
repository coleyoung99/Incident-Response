import socket
import subprocess
import smtplib
from collections import deque
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from scapy.all import sniff, IP, TCP, UDP, ICMP, ARP
import time

def read_credentials_from_file(file_path):
    with open(file_path, 'r') as file:
        lines = file.readlines()
        email = lines[0].strip()
        password = lines[1].strip()
    return email, password

def send_email(message, time_str, sender_email, sender_password):
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = "coleturneryoung@gmail.com"
    msg['Subject'] = "Warning Irregular Activity - {}".format(time_str)
   
    msg.attach(MIMEText(message, 'plain'))
   
    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(sender_email, sender_password)
        text = msg.as_string()
        server.sendmail(sender_email, "coleturneryoung@gmail.com", text)
       
        print("Email sent successfully!")
    except Exception as e:
        print("Email could not be sent:", str(e))
    finally:
        server.quit()

def detect_attack(packet):
    global echo_requests, syn_packets, tcp_reset_counts, ping_of_death_ips, arp_responses, arp_ips
   
    # Check if packet contains IP layer
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        target_ip = packet[IP].dst

        if packet.haslayer(ICMP) and packet[ICMP].type == 8:
            # ICMP ping of death detection
            if len(packet) >= 1500:
                if src_ip not in ping_of_death_ips:
                    print("ICMP Ping of Death detected from source:", src_ip)
                    send_email("ICMP Ping of Death detected from source: {0}, Target IP: {1}".format(src_ip, target_ip), time.strftime("%Y-%m-%d %H:%M:%S"), sender_email, sender_password)
                    ping_of_death_ips.append(src_ip)
            else:
                # ICMP ping flood detection
                echo_requests.append(time.time())
                if len(echo_requests) >= 10:
                    time_difference = echo_requests[-1] - echo_requests[0]
                    if time_difference <= 10:
                        if src_ip not in ping_flood_ips:
                            print("Possible ping flood detected")
                            send_email("Possible ping flood detected from source: {0}, Target IP: {1}".format(src_ip, target_ip), time.strftime("%Y-%m-%d %H:%M:%S"), sender_email, sender_password)
                            ping_flood_ips.append(src_ip)
       
        elif packet.haslayer(TCP):
            # TCP SYN flood detection
            if packet[TCP].flags & 2:
                if src_ip not in syn_packets:
                    syn_packets[src_ip] = 1
                else:
                    syn_packets[src_ip] += 1
                if syn_packets[src_ip] > 100:
                    if src_ip not in tcp_syn_flood_ips:
                        print("Possible TCP SYN flooding attack detected")
                        send_email("Possible TCP SYN flooding attack detected from source: {0}, Target IP: {1}".format(src_ip, target_ip), time.strftime("%Y-%m-%d %H:%M:%S"), sender_email, sender_password)
                        tcp_syn_flood_ips.append(src_ip)

        elif UDP in packet:
            # UDP flood detection
            if src_ip not in udp_flood_counts:
                udp_flood_counts[src_ip] = 1
            else:
                udp_flood_counts[src_ip] += 1
           
            if udp_flood_counts[src_ip] > 100:
                if src_ip not in udp_flood_ips:
                    print("Possible UDP flood attack detected")
                    send_email("Possible UDP flood attack detected from source: {0}, Target IP: {1}".format(src_ip, target_ip), time.strftime("%Y-%m-%d %H:%M:%S"), sender_email, sender_password)
                    udp_flood_ips.append(src_ip)

    # Check if packet contains ARP layer
    elif packet.haslayer(ARP):
        arp_src_ip = packet[ARP].psrc
        arp_src_mac = packet[ARP].hwsrc
        target_ip = packet[ARP].pdst

        if arp_src_ip in arp_responses:
            if arp_responses[arp_src_ip] != arp_src_mac:
                if arp_src_ip not in arp_ips:
                    print("Possible ARP spoofing detected for IP:", arp_src_ip)
                    send_email("Possible ARP spoofing detected from  source: {0}, Target IP: {1}".format(arp_src_ip, target_ip), time.strftime("%Y-%m-%d %H:%M:%S"), sender_email, sender_password)
                    arp_ips.append(arp_src_ip)
        else:
            arp_responses[arp_src_ip] = arp_src_mac


# Initialize global variables
echo_requests = deque(maxlen=10)
syn_packets = {}
tcp_reset_counts = {}
ping_flood_ips = []
tcp_syn_flood_ips = []
ping_of_death_ips = []
udp_flood_counts = {}
udp_flood_ips = []
arp_responses = {}
arp_ips = []

# Read sender's email and password from file
sender_email, sender_password = read_credentials_from_file("credentials.txt")

# Sniff all packets and call detect_attack for each packet
sniff(prn=detect_attack)
