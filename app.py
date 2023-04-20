from flask import Flask, render_template, request, jsonify
import sqlite3
from scapy.all import *

# create Flask application
app = Flask(__name__)

# set up database connection
conn = sqlite3.connect('alerts.db', check_same_thread=False)
c = conn.cursor()

# create table for alerts
c.execute('''CREATE TABLE IF NOT EXISTS alerts
             (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, url TEXT, timestamp TEXT)''')
conn.commit()

# create table for whitelist
c.execute('''CREATE TABLE IF NOT EXISTS whitelist
             (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, url TEXT)''')
conn.commit()

# start the sniffer on the specified network interface
def start_sniffer(interface):
    sniff(iface=interface, prn=analyze_packet, filter='tcp port 80')

# analyze a single packet and store alerts in the database
def analyze_packet(packet):
    # check if packet is an HTTP request
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            # extract HTTP request data
            http_data = packet[Raw].load.decode('utf-8')
            http_lines = http_data.split('\n')
            ip = packet[IP].src
            url = http_lines[0].split()[1]
            timestamp = str(datetime.now())

            # check if URL is in whitelist
            if not is_whitelisted(ip, url):
                # store alert in database
                c.execute("INSERT INTO alerts (ip, url, timestamp) VALUES (?, ?, ?)", (ip, url, timestamp))
                conn.commit()

# check if an IP address or URL is whitelisted
def is_whitelisted(ip, url):
    c.execute("SELECT * FROM whitelist WHERE ip = ? OR url = ?", (ip, url))
    result = c.fetchone()
    return result is not None

# remove an IP address or URL from the whitelist
def remove_from_whitelist(id):
    c.execute("DELETE FROM whitelist WHERE id = ?", (id,))
    conn.commit()

# add an IP address or URL to the whitelist
def add_to_whitelist(ip, url):
    c.execute("INSERT INTO whitelist (ip, url) VALUES (?, ?)", (ip, url))
    conn.commit()

# return a list of alerts in JSON format
def get_alerts():
    c.execute("SELECT * FROM alerts ORDER BY timestamp DESC")
    result = c.fetchall()
    alerts = []
    for row in result:
        alerts.append({'id': row[0], 'ip': row[1], 'url': row[2], 'timestamp': row[3]})
    return jsonify(alerts)

# return a list of whitelisted items in JSON format
def get_whitelist():
    c.execute("SELECT * FROM whitelist")
    result = c.fetchall()
    whitelist = []
    for row in result:
        whitelist.append({'id': row[0], 'ip': row[1], 'url': row[2]})
    return jsonify(whitelist)

# serve the index page
