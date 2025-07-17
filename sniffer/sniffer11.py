from scapy.all import sniff, IP, TCP, UDP, ICMP, Raw # to capture and analyize network packets
from termcolor import colored # to enhance output by specifying colors to protocols(UDP. TCP, ICMP) and other output data
import csv # to make a csv format file of all sniffed packets as well as suspicious packets
import time # for timestamp
import requests # to communicate with web api here we'll use ip-api
from collections import defaultdict # auto create default value if key doesn't exist avoiding errors

# === CONFIG ===
CSV_LOG_FILE = 'all_sniffed_packets.csv' # log file for captured packets 
SUSPICIOUS_LOG_FILE = 'suspicious_packets.txt' # log file for only suspicious packets so we can analyze it later in detail
GEOIP_API = 'http://ip-api.com/json/' # Base url of GeoIp APi for meta data
#if 50 or more packets are recieved in 5 seconds then it'll be flagged as suspicious
SUSPICIOUS_THRESHOLD = 50  # No. of packets = 50
SUSPICIOUS_WINDOW = 5 #time window = 5 seconds

# === GLOBAL TRACKERS ===
ip_counter = defaultdict(list) # Tracks each IP with list of timestamps when packet arrives
ip_meta_cache = {} # caches meta data (country, ISP, organization, etc ) for each IP avoiding repeated API calls 

# === GET PAYLOAD DISPLAY MODE FROM USER ===
#displays payload format options to the user and returns the mode of user's choice 
#converts input into lowercase to avoid case-insensitvity issues
#if the input is invalid then default 'short' mode is used
def get_payload_mode():
    print(colored("Payload display options:", 'cyan'))
    print("1. short   → Only first few bytes")
    print("2. full    → Full (hex + ASCII) side-by-side")
    print("3. hex     → Hexadecimal only")
    print("4. ascii   → ASCII printable characters only")
    mode = input("Select payload display mode (short/full/hex/ascii): ").lower()
    if mode not in ['short', 'full', 'hex', 'ascii']: 
        print("Invalid mode. Defaulting to 'short'")
        return 'short'
    return mode

# === GEO & WHOIS LOOKUP ===

def get_ip_info(ip):
    #return cache meta data if available for the IP
    if ip in ip_meta_cache:
        return ip_meta_cache[ip]
    #default values
    result = {
        'country': 'Unknown',
        'isp': 'Unknown',
        'org': 'Unknown',
        'hosting': False,
        'proxy': False,
        'vpn': False
    }
    #API call to fetch metadata from ip-api
    #json() converts the fetched API response into a Python dictionary
    #Updates the result dictionary with the retrieved metadata
    try:
        res = requests.get(GEOIP_API + ip, timeout=2).json() 
        result['country'] = res.get('country', 'Unknown')
        result['isp'] = res.get('isp', 'Unknown')
        result['org'] = res.get('org', 'Unknown')
        result['hosting'] = res.get('hosting', False)
        result['proxy'] = res.get('proxy', False)
        result['vpn'] = res.get('mobile', False) or 'vpn' in res.get('org', '').lower()
    except:
        pass #use default values if Api call fails
    #cache result and return
    ip_meta_cache[ip] = result
    return result 

# === CSV LOGGER ===
def log_to_csv(timestamp, src, dst, proto, length, info): #define csv logger and parameters of the function
    #open the csv file in append mode and call it f for now
    with open(CSV_LOG_FILE, 'a', newline='') as f: 
        #writes new line in csv file with packet's meta data
        writer = csv.writer(f) 
        writer.writerow([
            timestamp,
            src,
            dst,
            info['country'],
            proto,
            length,
            info['isp'],
            info['org'],
            'Yes' if info['hosting'] else 'No',
            'Yes' if info['vpn'] else 'No',
            'Yes' if info['proxy'] else 'No'
        ])

# === LOG SUSPICIOUS PACKET ===
#logs suspicious packets into a file with packet meta data and its payload for later analysis
def log_suspicious(info, payload): 
    with open(SUSPICIOUS_LOG_FILE, 'a') as f: 
        f.write(f"{info}\n") 
        f.write(f"Payload:\n{payload}\n") 
        f.write("="*60 + "\n") 
# === DETECT SUSPICIOUS IP ===
# Detects if an IP has sent a suspicious number of packets within a short time window. here, if 20 or more packets are recieved in 5 seconds
'''def detect_suspicious(ip):
    now = time.time() 
    ip_counter[ip] = [t for t in ip_counter[ip] if now - t < SUSPICIOUS_WINDOW] # It filters the timestamp list to keep only those within the last 5 seconds. Old timestamps (outside the window) are removed.
    ip_counter[ip].append(now) 
    return len(ip_counter[ip]) >= SUSPICIOUS_THRESHOLD '''

def detect_suspicious(src_ip, dst_ip, dst_port):
    now = time.time()
    key = (src_ip, dst_ip, dst_port)  # More specific key
    ip_counter[key] = [t for t in ip_counter[key] if now - t < SUSPICIOUS_WINDOW]
    ip_counter[key].append(now)
    return len(ip_counter[key]) >= SUSPICIOUS_THRESHOLD
# === FORMAT PAYLOAD ===
# Formats the payload of a packet based on the selected display mode:
# 'short':first 20 bytes in hex
# 'full' :hex + ASCII side by side (16 bytes per line)
# 'hex'  :full hex only
# 'ascii':printable ASCII characters only
# Returns "[No Payload]" if the Raw layer is missing, or "[Unknown Mode]" if an invalid mode is provided.
def format_payload(packet, mode): 
    #checks if the packet has Raw layer
    if not packet.haslayer(Raw): 
        return "[No Payload]"
    #converts raw payload (stored in the 'load' attribute of the Raw layer) into bytes for processing
    data = bytes(packet[Raw].load) 
    if mode == 'short': 
        return data[:20].hex() + ('...' if len(data) > 20 else '')

    elif mode == 'full': 
        lines = [] 
        for i in range(0, len(data), 16): #16 bytes block per line i.e. step
            hex_part = ' '.join(f"{b:02x}" for b in data[i:i+16]) 
            ascii_part = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16]) 
            lines.append(f"{hex_part:<48}  {ascii_part}") 
        return '\n'.join(lines) 
    
    elif mode == 'hex': 
        return data.hex(' ')

    elif mode == 'ascii': 
        return ''.join(chr(b) if 32 <= b < 127 else '.' for b in data) 
    
    else:
        return "[Unknown Mode]" 

# === PROCESS PACKET ===
#extracts and processes relevant data from the captured packet: displays key info, logs it, and flags suspicious activity.
def process_packet(packet): 
    if IP in packet: 
        timestamp = time.strftime("%H:%M:%S", time.localtime()) 
        src = packet[IP].src 
        dst = packet[IP].dst 
        length = len(packet) 
        proto = 'OTHER'
        # detect protocol
        if TCP in packet:
            proto = 'TCP'
        elif UDP in packet:
            proto = 'UDP'
        elif ICMP in packet:
            proto = 'ICMP'
       
        color_map = {'TCP': 'green', 'UDP': 'yellow', 'ICMP': 'cyan', 'OTHER': 'white'}
        color = color_map.get(proto, 'white')
        #get meta data for source IP
        info = get_ip_info(src) 
        payload_display = format_payload(packet, PAYLOAD_MODE) 
        
        # Show packet summary
        summary = (
            f"[{timestamp}] Source: {src} ({info['country']}) → Destination: {dst} | {proto} | {length} bytes"
        )
        print(colored(summary, color))

        # Show Metadata/ GeoIp Info
        print(colored(f"└─ ISP       : {info['isp']}", 'yellow'))
        print(colored(f"└─ Org       : {info['org']}", 'yellow'))
        print(colored(f"└─ Hosting?  : {'Yes' if info['hosting'] else 'No'}", 'cyan'))
        print(colored(f"└─ VPN?      : {'Yes' if info['vpn'] else 'No'}", 'cyan'))
        print(colored(f"└─ Proxy?    : {'Yes' if info['proxy'] else 'No'}", 'cyan'))

        # Show Payload
        if payload_display:
            print(colored(f"Payload ({PAYLOAD_MODE}):", 'magenta'))
            print(payload_display)
            print()

        # Save to CSV
        log_to_csv(timestamp, src, dst, proto, length, info)

        # Suspicious detection
            
        src = packet[IP].src
        dst = packet[IP].dst
        port = packet[TCP].dport if packet.haslayer(TCP) else 0  # Or UDP

        if detect_suspicious(src, dst, port):
             print(colored("⚠ Potential DoS or Suspicious Activity!", 'red', attrs=['bold']))
             log_suspicious(summary, payload_display)

# === MAIN FUNCTION ===
def start_sniffer():
    print(colored(">>> Enhanced Python Network Sniffer Started <<<", 'blue', attrs=['bold']))
    print(colored("Press Ctrl+C to stop\n", 'magenta'))
    #get protocol filter from user input
    filter_input = input("Enter protocol to filter (tcp/udp/icmp/all): ").lower()
    if filter_input not in ['tcp', 'udp', 'icmp', 'all']:
        print("Invalid input. Defaulting to 'all'")
        filter_input = 'all'
    bpf_filter = filter_input if filter_input != 'all' else ''

    # Initilize CSV file with column headers
    with open(CSV_LOG_FILE, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Time', 'Source IP', 'Destination IP',
            'Country', 'Protocol', 'Length',
            'ISP', 'Organization',
            'Hosting?', 'VPN?', 'Proxy?'
        ])
    #start sniffing packets with filter process and display each one 
    try:
        while True:
            sniff(filter=bpf_filter, prn=process_packet, store=False, timeout=3)
            time.sleep(0.2)
    except KeyboardInterrupt:
        print(colored("\nSniffer stopped by user.", 'cyan'))

# === RUN ===
if __name__ == "__main__":
    #set payload mode and start sniffer
    PAYLOAD_MODE = get_payload_mode()
    start_sniffer() 