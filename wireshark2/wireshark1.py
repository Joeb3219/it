#!/usr/bin/python
# 
# This is the skeleton of the CS 352 Wireshark Assignment 1
#
# (c) 2018, R. P. Martin, GPL version 2

# Given a pcap file as input, you should report:
#
#1) number of the packets (use number_of_packets), 
#2) list distinct source IP addresses and number of packets for each IP address, in descending order 
#3) list distinct destination TCP ports and number of packers for each port(use list_of_tcp_ports, in descending order)
#4) The number of distinct source IP, destination TCP port pairs, in descending order 

import dpkt
import socket
import argparse 
from dpkt.ip import IP 
from dpkt.tcp import TCP
from collections import OrderedDict
import operator

# this helper method will turn an IP address into a string
def inet_to_str(inet):
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)

# main code 
def main():
    number_of_packets = 0             # you can use these structures if you wish 
    list_of_ips = dict()
    list_of_tcp_ports = dict()
    list_of_ip_tcp_ports = dict()

    # parse all the arguments to the client 
    parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 1')
    parser.add_argument('-f','--filename', help='pcap file to input', required=True)

    # get the filename into a local variable
    args = vars(parser.parse_args())
    filename = args['filename']

    # open the pcap file for processing 
    input_data=dpkt.pcap.Reader(open(filename,'r'))


    # this main loop reads the packets one at a time from the pcap file
    for timestamp, packet in input_data:
        ethernet = dpkt.ethernet.Ethernet(packet)
        data = ethernet.data
        # Add to number of total packets
        number_of_packets += 1

        if type(data) is IP:
            ip_dotted = inet_to_str(data.src)
            # Add source to the IP list
            if ip_dotted not in list_of_ips:
                list_of_ips[ip_dotted] = 0
            list_of_ips[ip_dotted] += 1


            if type(data.data) is TCP:
                tcp = data.data
                
                if tcp.dport not in list_of_tcp_ports:
                    list_of_tcp_ports[tcp.dport] = 0
                list_of_tcp_ports[tcp.dport] += 1

                ip_dst = inet_to_str(data.src) + ":" + str(tcp.dport)
                if ip_dst not in list_of_ip_tcp_ports:
                    list_of_ip_tcp_ports[ip_dst] = 0
                list_of_ip_tcp_ports[ip_dst] += 1
#                print("%s:%d => %s:%d" % (inet_to_str(data.src), tcp.sport, inet_to_str(data.dst), tcp.dport));
        

    print("Total number of packets, %d" % number_of_packets)

    sorted_listOfIps = sorted(list_of_ips.items(), key = operator.itemgetter(1), reverse=True)
    print("Source IP addresse, count")
    for ip, count in sorted_listOfIps:
        print("%s, %d" % (ip, count));

    sorted_listOfTcpPorts = sorted(list_of_tcp_ports.items(), key = operator.itemgetter(1), reverse=True)
    print("Destination TCP ports, count")
    for key, count in sorted_listOfTcpPorts:
        print("%s, %d" % (key, count));

    sorted_listOfIpTcpPorts = sorted(list_of_ip_tcp_ports.items(), key = operator.itemgetter(1), reverse=True) 
    print("Source IPs/Destination TCP ports, count")
    for key, count in sorted_listOfIpTcpPorts:
        print("%s, %d" % (key, count));



# execute a main function in Python
if __name__ == "__main__":
    main()    
