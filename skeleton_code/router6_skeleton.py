from socket import *
import sys
import traceback
from threading import Thread
from operator import *


# Helper Functions

# The purpose of this function is to set up a socket connection.
def create_socket(host, port):
    soc = socket(AF_INET,SOCK_STREAM) # 1. Create a socket.
    
    try: # 2. Try connecting the socket to the host and port.
        soc.connect((host,port))
    except:
        print("Connection Error to", port)
        sys.exit()
    return soc  # 3. Return the connected socket.


# The purpose of this function is to read in a CSV file.
def read_csv(path):
    table_file = open(path, "r") # 1. Open the file for reading.
    table = table_file.readlines() # 2. Store each line.
    table_list = [] # 3. Create an empty list to store each processed row.
    
    for line in table : # 4. For each line in the file:
        row = line.strip().split(',')# 5. split it by the delimiter,
        table_list.append([element.strip() for element in row]) # 6. remove any leading or trailing spaces in each element, and #7. append the resulting list to table_list.
    table_file.close() # 8. Close the file and return table_list.
    return table_list


# The purpose of this function is to find the default port
# when no match is found in the forwarding table for a packet's destination IP.
def find_default_gateway(table):
    
    for row in table: # 1. Traverse the table, row by row,
        if row[0] == '0.0.0.0':# 2. and if the network destination of that row matches 0.0.0.0,
            return row[3] # 3. then return the interface of that row.
        


# The purpose of this function is to generate a forwarding table that includes the IP range for a given interface.
# In other words, this table will help the router answer the question:
# Given this packet's destination IP, which interface (i.e., port) should I send it out on?
def generate_forwarding_table_with_range(table):
    new_table = [] # 1. Create an empty list to store the new forwarding table.
    for row in table: # 2. Traverse the old forwarding table, row by row,
        if row[0] != '0.0.0.0': # 3. and process each network destination other than 0.0.0.0 (0.0.0.0 is only useful for finding the default port).
            network_dst_string = row[0] # 4. Store the network destination and netmask.
            netmask_string = row[1]
            network_dst_bin = ip_to_bin(network_dst_string) # 5. Convert both strings into their binary representations.
            netmask_bin = ip_to_bin(netmask_string)
            ip_range = find_ip_range(network_dst_bin, netmask_bin)  # 6. Find the IP range.
            new_row =  [network_dst_string, netmask_string, row[3], (ip_range[0]), (ip_range[1]) ]# 7. Build the new row.
            
            new_table.append(new_row) # 8. Append the new row to new_table.
    
    return new_table # 9. Return new_table.


# The purpose of this function is to convert a string IP to its binary representation.
def ip_to_bin(ip):
    ip_octets = ip.split('.') # 1. Split the IP into octets.
    ip_bin_string = "" # 2. Create an empty string to store each binary octet.
    for octet in ip_octets: # 3. Traverse the IP, octet by octet
        int_octet = int(octet) # 4. and convert the octet to an int
        #print(int_octet)
        bin_octet = bin(int_octet) # 5. convert the decimal int to binary,
        #print(bin_octet)
        bin_octet_string = bin_octet[2:] # 6. convert the binary to string and remove the "0b" at the beginning of the string
        #print(bin_octet_string)
        while len(bin_octet_string) < 8:# 7. while the string representation of the binary is not 8 chars long, then add 0s to the beginning of the string until it is 8 chars long (needs to be an octet because we're working with IP addresses).
            bin_octet_string = '0' + bin_octet_string
        ip_bin_string += bin_octet_string # 8. Finally, append the octet to ip_bin_string.
    #print(ip_bin_string)
    ip_int = int(ip_bin_string, 2) # 9. Once the entire string version of the binary IP is created, convert it into an actual binary int.
    #print(bin(ip_int))
    return bin(ip_int) # 10. Return the binary representation of this int.


# The purpose of this function is to find the range of IPs inside a given a destination IP address/subnet mask pair.
def find_ip_range(network_dst, netmask):
    #print(network_dst)
    #print(netmask)
    bitwise_and = int(network_dst, 2) & int(netmask, 2) # 1. Perform a bitwise AND on the network destination and netmask to get the minimum IP address in the range.
    #print(bitwise_and)
    compliment = bit_not(int(netmask, 2)) # 2. Perform a bitwise NOT on the netmask to get the number of total IPs in this range. Because the built-in bitwise NOT or compliment operator (~) works with signed ints, we need to create our own bitwise NOT operator for our unsigned int (a netmask).
    min_ip = bitwise_and # 3. Add the total number of IPs to the minimum IP to get the maximum IP address in the range.
    max_ip = min_ip + compliment
    min2 = str(bin(min_ip))[2:]
    max2 = str(bin(max_ip))[2:]
    while len(min2) < 32:
        min2 = '0' + min2
    while len(max2) < 32:
        max2 = '0' + max2
    return [min2, max2] # 4. Return a list containing the minimum and maximum IP in the range. 


# The purpose of this function is to perform a bitwise NOT on an unsigned integer.
def bit_not(n, numbits=32):
    return (1 << numbits) - 1 - n


# The purpose of this function is to receive and process an incoming packet.
def receive_packet(connection, max_buffer_size):
    # 1. Receive the packet from the socket.
    received_packet = connection.recv(max_buffer_size).decode('utf-8')
    
    # 2. If the packet size is larger than the max_buffer_size, print a debugging message
    packet_size = sys.getsizeof(received_packet)
    if packet_size > max_buffer_size:
        print("The packet size is greater than expected", packet_size)
    
    # 3. Decode the packet and strip any trailing whitespace.
    decoded_packet = received_packet.strip()
    
    # 3. Append the packet to received_by_router_2.txt.
    write_to_file('../output/received_by_router_6.txt', decoded_packet)
    
    # 4. Split the packet by the delimiter (assuming ',' as the delimiter).
    packet = decoded_packet.split(',')
    
    # 5. Return the list representation of the packet.
    return packet


# The purpose of this function is to write packets/payload to file.
def write_to_file(path, packet_to_write, send_to_router=None):
    out_file = open(path, "a") # 1. Open the output file for appending.
    if send_to_router is None: # 2. If this router is not sending, then just append the packet to the output file.
        out_file.write(packet_to_write + "\n")
    else: # 3. Else if this router is sending, then append the intended recipient, along with the packet, to the output file.
        out_file.write(packet_to_write + " " + "to Router " + send_to_router + "\n")
    out_file.close() # 4. Close the output file.


# The purpose of this function is to
# (a) create a server socket,
# (b) listen on a specific port,
# (c) receive and process incoming packets,
# (d) forward them on, if needed.
def start_server():
    # 1. Create a socket.
    host = '127.0.0.1'
    port = 8006
    soc = socket(AF_INET, SOCK_STREAM)
    soc.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    print("Socket created")

    # 2. Try binding the socket to the appropriate host and receiving port (based on the network topology diagram).
    try:
        soc.bind((host, port))
    except:
        print("Bind failed. Error: " + str(sys.exc_info()))
        sys.exit()

    # 3. Set the socket to listen.
    soc.listen(1)
    print("Socket now listening")

    # 4. Read in and store the forwarding table.
    forwarding_table = read_csv('../input/router_6_table.csv')
    # 5. Store the default gateway port.
    default_gateway_port = find_default_gateway(forwarding_table)  # Assuming you have a find_default_gateway function
    # 6. Generate a new forwarding table that includes the IP ranges for matching against destination IPS.
    forwarding_table_with_range = generate_forwarding_table_with_range(forwarding_table)

    # 7. Continuously process incoming packets.
    while True:
        # 8. Accept the connection.
        connection, address = soc.accept()
        ip, port = address
        print("Connected with " + ip + ":" + str(port))

        # 9. Start a new thread for receiving and processing the incoming packets.
        try:
            thread = Thread(target=processing_thread, args=(connection, ip, str(port), forwarding_table_with_range, default_gateway_port)) #How to do this line?
            thread.start()
        except:
            print("Thread did not start.")
            traceback.print_exc()

# The purpose of this function is to receive and process incoming packets.
def processing_thread(connection, ip, port, forwarding_table_with_range, default_gateway_port, max_buffer_size=5120):
    # 1. Connect to the appropriate sending ports (based on the network topology diagram).
    # router3_port = 8003  
    # router4_port = 8004 

    #router3_socket = socket(AF_INET, SOCK_STREAM)
    #router3_socket.connect(('127.0.0.1', router3_port))
    #router4_socket = socket(AF_INET, SOCK_STREAM)
    #router4_socket.connect(('127.0.0.1', router4_port))
    

    # 2. Continuously process incoming packets
    while True:
        # 3. Receive the incoming packet, process it, and store its list representation
        packet = receive_packet(connection, max_buffer_size)

        # 4. If the packet is empty (Router 1 has finished sending all packets), break out of the processing loop
        if len(packet) <= 1:
            break

        # 5. Store the source IP, destination IP, payload, and TTL.
        sourceIP = packet[0]
        destinationIP = packet[1]
        payload = packet[2]
        ttl = packet[3]

        # 6. Decrement the TTL by 1 and construct a new packet with the new TTL.
        new_ttl = str(int(ttl) - 1)
        new_packet = f"{sourceIP},{destinationIP},{payload},{new_ttl}"

        # 7. Convert the destination IP into an integer for comparison purposes.
        destinationIP_bin = ip_to_bin(destinationIP)
        destinationIP_int = int(destinationIP_bin, 2)

        # 8. Find the appropriate sending port to forward this new packet to.
        port = None
        for row in forwarding_table_with_range:
            #print(row)
            min_ip, max_ip = row[3], row[4]
            if int(min_ip,2) <= destinationIP_int and destinationIP_int <= int(max_ip,2):
                port = row[2]
                break

        # 9. If no port is found, then set the sending port to the default port.
        if port == None:
            port = default_gateway_port

        # 11. Either
        # (a) send the new packet to the appropriate port (and append it to sent_by_router_2.txt),
        # (b) append the payload to out_router_2.txt without forwarding because this router is the last hop, or
        # (c) append the new packet to discarded_by_router_2.txt and do not forward the new packet

        if port == '127.0.0.1':
            print("OUT:", payload)
            write_to_file('../output/out_router_6.txt', payload)
        else:
            print("DISCARD:", new_packet)
            write_to_file('../output/discarded_by_router_6.txt', new_packet)


# Main Program

# 1. Start the server.
start_server()
