from scapy.all import sniff
from datetime import datetime
import logging

# Configure logging
LOG_FILE = "packets.log"
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)

# Packet processing function
def process_packet(packet):
    """
    Processes and logs packet information.
    """
    try:
        # Basic details
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        src_ip = packet["IP"].src if packet.haslayer("IP") else "N/A"
        dst_ip = packet["IP"].dst if packet.haslayer("IP") else "N/A"
        protocol = packet["IP"].proto if packet.haslayer("IP") else "N/A"
        
        # Packet summary
        packet_summary = f"Time: {timestamp}, Source: {src_ip}, Destination: {dst_ip}, Protocol: {protocol}"
        print(packet_summary)
        
        # Log packet to file
        logging.info(packet_summary)

        # Additional information for TCP/UDP packets
        if packet.haslayer("TCP"):
            logging.info(f"TCP Packet: Src Port={packet['TCP'].sport}, Dst Port={packet['TCP'].dport}")
        elif packet.haslayer("UDP"):
            logging.info(f"UDP Packet: Src Port={packet['UDP'].sport}, Dst Port={packet['UDP'].dport}")

    except Exception as e:
        print(f"Error processing packet: {e}")
        logging.error(f"Error processing packet: {e}")

def main():
    """
    Starts the packet sniffer.
    """
    print("Starting Packet Sniffer...")
    print("Packets will be logged to 'packets.log'")
    print("Press Ctrl+C to stop sniffing.")
    
    try:
        # Sniff packets on all interfaces
        sniff(prn=process_packet, store=False)
    except KeyboardInterrupt:
        print("\nStopping Packet Sniffer...")
        logging.info("Packet sniffer stopped by user.")

if __name__ == "__main__":
    main()
