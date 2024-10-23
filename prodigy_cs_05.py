from scapy.all import sniff, conf

conf.L3socket

# Function to process each captured packet
def packet_callback(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        protocol = packet['IP'].proto
        
        # Initialize ports
        src_port = None
        dst_port = None

        # Check if the packet is TCP
        if packet.haslayer('TCP'):
            src_port = packet['TCP'].sport
            dst_port = packet['TCP'].dport
        
        # Check if the packet is UDP
        elif packet.haslayer('UDP'):
            src_port = packet['UDP'].sport
            dst_port = packet['UDP'].dport
        
        # Get the payload data
        if packet.haslayer('Raw'):
            payload = bytes(packet['Raw'])  # Convert the payload to bytes for display
            
            # Print the payload in hex format
            payload_hex = payload.hex()  # Convert to hexadecimal representation
            payload_ascii = payload.decode('utf-8', 'ignore')  # Decode to ASCII, ignoring errors
            
            # Print all details in a structured format
            print(f"Source IP: {src_ip} | Source Port: {src_port}")
            print(f"Destination IP: {dst_ip} | Destination Port: {dst_port}")
            print(f"Protocol: {protocol}")
            print(f"Payload (Hex): {payload_hex}")
            print(f"Payload (ASCII): {payload_ascii}\n")
        else:
            # Print without raw data
            print(f"Source IP: {src_ip} | Source Port: {src_port}")
            print(f"Destination IP: {dst_ip} | Destination Port: {dst_port}")
            print(f"Protocol: {protocol}")
            print("Payload: No Raw Data\n")


sniff(filter="ip", prn=packet_callback)
