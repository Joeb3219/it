#!/usr/bin/env python

import dpkt
import datetime
import socket
import argparse
from dpkt.ip import IP 
from dpkt.tcp import TCP
import operator


# convert IP addresses to printable strings 
def inet_to_str(inet):
	# First try ipv4 and then ipv6
	try:
		return socket.inet_ntop(socket.AF_INET, inet)
	except ValueError:
		return socket.inet_ntop(socket.AF_INET6, inet)

# add your own function/class/method defines here.

def main():
	# parse all the arguments to the client
	parser = argparse.ArgumentParser(description='CS 352 Wireshark Assignment 2')
	parser.add_argument('-f', '--filename', type=str, help='pcap file to input', required=True)
	parser.add_argument('-t', '--targetip', type=str, help='a target IP address', required=True)
	parser.add_argument('-l', '--wp', type=int, help='Wp', required=True)
	parser.add_argument('-m', '--np', type=int, help='Np', required=True)
	parser.add_argument('-n', '--ws', type=int, help='Ws', required=True)
	parser.add_argument('-o', '--ns', type=int, help='Ns', required=True)

	# get the parameters into local variables
	args = vars(parser.parse_args())
	file_name = args['filename']
	target_ip = args['targetip']
	W_p = args['wp']
	N_p = args['np']
	W_s = args['ws']
	N_s = args['ns']

	input_data = dpkt.pcap.Reader(open(file_name,'r'))

	port_tcp = list()
	time_tcp = list()
	port_udp = list()
	time_udp = list()

	for timestamp, packet in input_data:
		# this converts the packet arrival time in unix timestamp format
		# to a printable-string
		time_string = datetime.datetime.utcfromtimestamp(timestamp)
		ethernet = dpkt.ethernet.Ethernet(packet)
		data = ethernet.data

		if type(data) is IP:
			addy = data.src

			if inet_to_str(data.dst) != target_ip:
				continue;

			if type(data.data) is TCP:
				tcp = data.data
				port = tcp.dport
				
				obj = (port, time_string, inet_to_str(data.src));
				port_tcp.append(obj);
				time_tcp.append(obj);

			if data.p == dpkt.ip.IP_PROTO_UDP:
				udp = data.data
				port = udp.dport

				obj = (port, time_string, inet_to_str(data.src));
				port_udp.append(obj);
				time_udp.append(obj);

	port_tcp.sort(key=lambda x: x[0], reverse=False)
	time_tcp.sort(key=lambda x: x[1], reverse=False)
	port_udp.sort(key=lambda x: x[0], reverse=False)
	time_udp.sort(key=lambda x: x[1], reverse=False)

	scan_tdp = [[]];
	scan_udp = [[]];
	probe_tdp = [[]];
	probe_udp = [[]];

	num_probe_tdp = 0;
	num_probe_udp = 0;
	num_scan_tdp = 0;
	num_scan_udp = 0;
	for index, tup in enumerate(port_tcp):
		currList = probe_tdp[-1];
		if index == 0:
			currList.append(tup);
		else:
			if len(currList) == 0:
				currList.append(tup);
			else:
				previous = currList[-1];
				if (previous[0] != tup[0]):
					newList = [tup];
					probe_tdp.append(newList);
				elif (abs((tup[1] - previous[1]).total_seconds())) > W_p:
					newList = [tup];
					probe_tdp.append(newList);
				else:
					currList.append(tup);

	for lst in probe_tdp:
		if(len(lst) >= N_p):
			num_probe_tdp += 1;


	for index, tup in enumerate(port_tcp):
		if(index == 0):
			scan_tdp[0].append(tup);
		else:
			foundMatch = False;	
			for lst in scan_tdp:
				firstElement = lst[0];
				lastElement = lst[-1];
				if(tup[0] < (firstElement[0] - W_s)):
					continue;
				elif(tup[0] < firstElement[0] and (abs(tup[0] - firstElement[0])) < W_s):
					lst.insert(0, tup);
					foundMatch = True;
				elif(tup[0] > (lastElement[0] + W_s)):
					continue;
				elif(tup[0] > lastElement[0]):
					lst.insert(len(lst), tup);
					foundMatch = True;
				else:
					lst.insert(1, tup);
					foundMatch = True;
			if (not foundMatch):
				scan_tdp.append([tup]);

	for lst in scan_tdp:
		if (len(lst) >= N_s):
			num_scan_tdp += 1;

	for index, tup in enumerate(port_udp):
		if(index == 0):
			scan_udp[0].append(tup);
		else:
			foundMatch = False;	
			for lst in scan_udp:
				firstElement = lst[0];
				lastElement = lst[-1];
				if(tup[0] < (firstElement[0] - W_s)):
					continue;
				elif(tup[0] < firstElement[0] and (abs(tup[0] - firstElement[0])) < W_s):
					lst.insert(0, tup);
					foundMatch = True;
				elif(tup[0] > (lastElement[0] + W_s)):
					continue;
				elif(tup[0] > lastElement[0]):
					lst.insert(len(lst), tup);
					foundMatch = True;
				else:
					lst.insert(1, tup);
					foundMatch = True;
			if (not foundMatch):
				scan_udp.append([tup]);

	for lst in scan_udp:
		if (len(lst) >= N_s):
			num_scan_udp += 1;

	for index, tup in enumerate(port_udp):
		currList = probe_udp[-1];
		if index == 0:
			currList.append(tup);
		else:
			if len(currList) == 0:
				currList.append(tup);
			else:
				previous = currList[-1];
				if (previous[0] != tup[0]):
					newList = [tup];
					probe_udp.append(newList);
				elif (abs((tup[1] - previous[1]).total_seconds())) > W_p:
					newList = [tup];
					probe_udp.append(newList);
				else:
					currList.append(tup);

	for lst in probe_udp:
		if(len(lst) >= N_p):
			num_probe_udp += 1;

	# print time
	print("Reports for TCP");
	probe_tdp.sort(key=lambda x: len(x), reverse=True)
	print("Found %d probes" % (num_probe_tdp));
	for index, lst in enumerate(probe_tdp):
		if (len(lst) >= N_p):
			print("Probe: [%d packets]" % (len(lst)));
			for pkt in lst:
				print("Packet [Timestamp: %s, Port: %d, Source IP: %s]" % (pkt[1], pkt[0], pkt[2]));

	scan_tdp.sort(key=lambda x: len(x), reverse=True)
	print("Found %d scans" % (num_scan_tdp));
	for index, lst in enumerate(scan_tdp):
		if (len(lst) >= N_s):
			lst.sort(key=lambda x: x[1], reverse=False);
			print("Scan: [%d packets]" % (len(lst)));
			for pkt in lst:
				print("Packet [Timestamp: %s, Port: %d, Source IP: %s]" % (pkt[1], pkt[0], pkt[2]));

	print("Reports for UDP");
	probe_udp.sort(key=lambda x: len(x), reverse=True)
	print("Found %d probes" % (num_probe_udp));
	for index, lst in enumerate(probe_udp):
		if (len(lst) >= N_p):
			print("Probe: [%d packets]" % (len(lst)));
			for pkt in lst:
				print("Packet [Timestamp: %s, Port: %d, Source IP: %s]" % (pkt[1], pkt[0], pkt[2]));

	scan_udp.sort(key=lambda x: len(x), reverse=True)
	print("Found %d scans" % (num_scan_udp));
	for index, lst in enumerate(scan_udp):
		if (len(lst) >= N_s):
			lst.sort(key=lambda x: x[1], reverse=False);
			print("Scan: [%d packets]" % (len(lst)));
			for pkt in lst:
				print("Packet [Timestamp: %s, Port: %d, Source IP: %s]" % (pkt[1], pkt[0], pkt[2]));

# execute a main function in Python
if __name__ == "__main__":
	main()
