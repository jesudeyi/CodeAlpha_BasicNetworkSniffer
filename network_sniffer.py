# network_sniffer.py
# CodeAlpha Cyber Security Task 1: Basic Network Sniffer

from scapy.all import sniff, IP, TCP, UDP, ICMP
import sys

def packet_callback(packet):
    """
    This function is called for every packet captured by Scapy's sniff().
    It analyzes the packet and prints key information.
    """
    
    # Check if the packet has an IP layer (Layer 3)
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol_num = ip_layer.proto
        protocol_name = "Unknown"
        
        # Determine the protocol name based on the protocol number
        # 6=TCP, 17=UDP, 1=ICMP
        if protocol_num == 6:
            protocol_name = "TCP"
        elif protocol_num == 17:
            protocol_name = "UDP"
        elif protocol_num == 1:
            protocol_name = "ICMP"
            
        # Print the extracted IP and Protocol information
        print(f"\n{'='*50}")
        print(f"Protocol: **{protocol_name}**")
        print(f"Source IP: **{src_ip}**")
        print(f"Destination IP: **{dst_ip}**")
        
        # --- Check for Transport Layer (TCP/UDP) to get ports ---
        
        if TCP in packet:
            src_port = packet[TCP].sport
            dst_port = packet[TCP].dport
            print(f"  |-- Source Port: {src_port}, Destination Port: {dst_port}")
            
        elif UDP in packet:
            src_port = packet[UDP].sport
            dst_port = packet[UDP].dport
            print(f"  |-- Source Port: {src_port}, Destination Port: {dst_port}")
            
        # --- Check for Payload (Raw data) ---
        
        if 'Raw' in packet:
            payload = packet['Raw'].load
            try:
                # Try to decode as text (UTF-8) for readability
                decoded_payload = payload.decode('utf-8', errors='ignore')
                print(f"  |-- Payload (Decoded): {decoded_payload[:70]}...")
            except:
                # If decoding fails, print the raw byte representation
                print(f"  |-- Payload (Raw Bytes): {repr(payload)[:70]}...")

        print(f"{'='*50}")

def main():
    """
    Main function to start the sniffer and handle user exit.
    """
    print("[*] Starting Basic Network Sniffer... Press Ctrl+C to stop.")
    
    try:
        # Start sniffing. 
        # prn=packet_callback: Run this function for each packet.
        # filter="ip": Only capture IP packets.
        # store=0: Do not store packets in memory (saves resources).
        sniff(prn=packet_callback, filter="ip", store=0)
    
    except KeyboardInterrupt:
        # Handle the user pressing Ctrl+C
        print("\n[*] Sniffer stopped by user.")
        sys.exit(0)
    except Exception as e:
        # Handle other errors (e.g., permission denied)
        print(f"\n[!] An error occurred: {e}")
        print("[!] Note: This tool must be run with elevated privileges (sudo/Administrator).")
        sys.exit(1)

# Standard Python entry point
if __name__ == "__main__":
    main()