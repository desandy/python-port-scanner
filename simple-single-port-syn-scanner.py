#!/usr/bin/env python

from scapy.all import *
import time
import optparse

# Grab parameters for scan
parser = optparse.OptionParser()
parser.add_option('-a', '--addr', dest='addr')
(options, args) = parser.parse_args()

# Grab the start time
start_time = time.time()

# Upper limit on TCP Ports is 65535
# Services can be configured to run on almost any port
for dst_port in range(1, 10):

    # Set the IP DST Address Field
    # Set the TCP DST Port Field
    tcp_request = IP(dst = options.addr)/TCP(dport = dst_port, flags = "S")

    # Send 1 packet and grab the response
    tcp_response = sr1(tcp_request, timeout = 1, verbose = 0)

    # Open ports should respond with SYN/ACK.
    # Closed ports with RST/ACK
    # No response should indicate a filtered port
    if tcp_response == None:
        print("[-] Port %i is filtered." % (dst_port))
        continue
    try:        
        if tcp_response.getlayer(TCP).flags == "SA":
            print("[+] Port %i is open." % (dst_port))
        if tcp_response.getlayer(TCP).flags == "RA":
            print("[-] Port %i is closed." % (dst_port))
    except AttributeError:
        print("[!] Port %i returned a non-compliant response." % (dst_port))

# Grab the completion time and subtract the start time
duration = time.time() - start_time
print("Scan completed in %fs seconds." % (duration))
