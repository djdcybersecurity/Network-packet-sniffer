# Network-packet-sniffer
    A powerful Python-based tool to capture, log, and analyze network packets in real-time using the Scapy library.



# Features 
    Captures all incoming and outgoing network packets.
    Logs packet details, including:
    Source and destination IPs.
    Protocols (TCP, UDP, ICMP, etc.).
    Source and destination ports for TCP/UDP packets.
    Saves packet information to a packets.log file.
    Easy to configure with optional filtering for specific protocols.
    Extensible for exporting to PCAP format for use with Wireshark.


  # Requirements
    Operating System: Linux-based (tested on Ubuntu)
    Python Version: Python 3.8+
    Dependencies:
    Scapy


  # Installation
      1. Clone the Repository
            git clone https://github.com/djdcybersecurity/Network-packet-sniffer.git
            cd Network-packet-sniffer

      2. Set Up a Virtual Environment
            python3 -m venv packet_sniffer_env
            source packet_sniffer_env/bin/activate

      3. Install Dependencies
            pip install -r requirements.txt



  # Usage
        1. Run the Packet sniferr
            sudo python3 packet_sniffer.py           #The script requires sudo to access network interfaces for packet sniffing.


            
        2. Generate Network Traffic 
            ping google.com
            curl http://example.com


        
        3. Stop the Sniffer PRESS CTRL+C to stop the sniffer



        4. Analyze the logs View the packets.log file for detailed packet information:
            cat packets.log

            

  # Examples of Possible Outputs when you are done

        # Console Output
              Starting Packet Sniffer...
              Packets will be logged to 'packets.log'
              Press Ctrl+C to stop sniffing.

              Ether / IP / TCP 192.168.1.10:443 > 192.168.1.20:54321 Flags [P.] Seq=1 Ack=1 Win=1 ...


        # Log File
              Sample of content of packets.log:
              2024-12-07 12:30:00 - Time: 2024-12-07 12:30:00, Source: 192.168.1.10, Destination: 192.168.1.20, Protocol: 6
              2024-12-07 12:30:01 - TCP Packet: Src Port=443, Dst Port=54321
              2024-12-07 12:30:05 - Time: 2024-12-07 12:30:05, Source: 8.8.8.8, Destination: 192.168.1.20, Protocol: 1


  # Customization

        # Filter Traffic: Modify the sniff function in packet_sniffer.py to capture specific protocols
              # using python
              sniff(filter="tcp", prn=process_packet, store=False)

        # Save Packets to Pcap: Add Functionality to save packets for analysis in wireshark:
              # using python
              from scapy.utils import wrpcap
              wrpcap("packets.pcap", packet_dump)


# Contact
        # for questions or feedback, please contact:
        GithHub: djdcybersecurity




















      
