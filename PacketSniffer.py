from scapy.all import *

def get_user_input():
    interface = input("Enter the network interface (e.g., ens33, wlan0): ")

    #Optional Filter Option
    packet_filter = input("Enter a packet filter/Berkeley Packet Filter (BPF) Syntax (e.g., 'tcp', 'udp', 'ip', 'tcp and port 80') or Press Enter to capture all packets")
    if not packet_filter:
        packet_filter = None
    
    #Optional Packet Count
    try:
        packet_count_input = input("Enter the number of packets to capture (press Enter for continuous capture): ")
        packet_count = int(packet_count_input) if packet_count_input else None  # Set to None if no input
    except ValueError:
        packet_count = None # Default to None and Continous if the input is invalid

    #Optinal Timeout
    try:
        timeout_input = input("Enter the timeout in seconds (press Enter for no timeout): ")
        timeout = int(timeout_input) if timeout_input else None  # Set to None if no input
    except ValueError:
        timeout = None  # Default to None if the input is invalid
    
    #Optional want to save results in a text file
    save_to_file = input("Do you want to save the results to a text file? (yes/no): ").lower()
    save_to_file = save_to_file == 'yes' # Boolean comparison and assignment
    if save_to_file:
        file_name = input("Enter the name of the file to save results (e.g., 'output.txt'): ")
    else:
        file_name = None  # Default to None if not saving

    return interface,packet_filter,packet_count,timeout,save_to_file,file_name

#Gloabl Counter for packet
packet_index = 0

#Saving to file
def log_packet_to_file(packet_details, file_name="packet_capture.txt"):
    with open(file_name, "a") as f:
        f.write(packet_details + "\n")

def packet_sniffer(packet, save_to_file=False, file_name=None):
    global packet_index
    packet_index += 1

    packet_details = []
    packet_details.append("="*50)
    packet_details.append(f"Packet #{packet_index}")
    packet_details.append("="*50)

    #Display deatiled packet information
    packet_details.append(f"Summary: {packet.summary()}")

    if packet.haslayer(IP):
        packet_details.append(f"Source IP: {packet[IP].src}")
        packet_details.append(f"Destinaton IP: {packet[IP].dst}")
        packet_details.append(f"Protocol: {packet[IP].proto}")

    if packet.haslayer(TCP) or packet.haslayer(UDP):
        transport_layer = packet[TCP] if packet.haslayer(TCP) else packet[UDP]
        packet_details.append(f"Source Port: {transport_layer.sport}")
        packet_details.append(f"Destination Port: {transport_layer.dport}")

    #Check for and display the payload data
    if packet.haslayer(Raw):
        packet_details.append(f"Payload: {packet[Raw].load}")

    packet_details.append(f"Raw packet Bytes: {bytes(packet)}")
    packet_details = "\n".join(packet_details)

    #Print packet details to the console
    print(packet_details)

    if save_to_file:
        log_packet_to_file(packet_details, file_name)

def main():
    #Get user input for sniffing options
    interface, packet_filter, packet_count, timeout, save_to_file, file_name = get_user_input()
    #print(f"Interface: {interface}, Filter: {packet_filter}, Count: {packet_count}, Timeout: {timeout}")

    #Display a starting message
    print("\n" + "="*50)
    print(f"[*] Starting packet sniffer on interface: {interface}")
    print(f"[*] Filter: {packet_filter if packet_filter else 'None (Capturing all packets)'}")
    print(f"[*] Packet count: {'Continuous capture' if packet_count is None else packet_count}")
    print(f"[*] Timeout: {'No timeout' if timeout is None else f'{timeout} seconds'}")
    print(f"[*] Saving results to file: {'Yes' if save_to_file else 'No'}")
    print("="*50 + "\n")

    #start Sniffing with user defined options
    #lambda function creates a anonymous function in a single line
    #argument 'x' represents the captured packet by sniff()
    #lambda function then calls packet_sniffer(x, save_to_file, file_name), passing three arguments:

    # Prepare arguments for sniff()
    sniff_args = {
        'iface': interface,
        'prn': lambda x: packet_sniffer(x, save_to_file, file_name),
        'filter': packet_filter
    }
    
    # Add count and timeout only if they are valid
    if packet_count is not None:
        sniff_args['count'] = packet_count  # Add count if it's a valid number
    if timeout is not None:
        sniff_args['timeout'] = timeout  # Add timeout if it's a valid number

    # Start sniffing with user-defined options
    sniff(**sniff_args)

main()
