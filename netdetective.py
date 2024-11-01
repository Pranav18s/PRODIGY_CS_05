from scapy.all import *

# Define a function to handle captured packets
def packet_handler(packet):
    if packet.haslayer(IP):
        ip_layer = packet[IP]
        protocol = ip_layer.proto
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst

        if packet.haslayer(TCP):
            tcp_layer = packet[TCP]
            src_port = tcp_layer.sport
            dst_port = tcp_layer.dport
            protocol_name = "TCP"
        elif packet.haslayer(UDP):
            udp_layer = packet[UDP]
            src_port = udp_layer.sport
            dst_port = udp_layer.dport
            protocol_name = "UDP"
        else:
            return  # Ignore non-TCP/UDP packets

        # Print packet details
        print(f"Packet Captured:\n"
              f"\tSource IP: {src_ip}\n"
              f"\tDestination IP: {dst_ip}\n"
              f"\tProtocol: {protocol_name}\n"
              f"\tSource Port: {src_port}\n"
              f"\tDestination Port: {dst_port}\n"
              f"\tRaw Payload: {bytes(packet)}\n")

        # Log the packet details to a file
        with open("packet_log.txt", 'a') as log_file:
            log_file.write(f"Source IP: {src_ip}, Destination IP: {dst_ip}, "
                           f"Protocol: {protocol_name}, Source Port: {src_port}, "
                           f"Destination Port: {dst_port}, Raw Payload: {bytes(packet)}\n")

# Start sniffing packets
print("Starting packet capture. Press Ctrl+C to stop.")
sniff(prn=packet_handler, filter="ip", store=0)
