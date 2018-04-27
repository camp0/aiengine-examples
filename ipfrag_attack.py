#!/usr/bin/env python

""" Example for detect IP Fragmentation attacks on the network """

import sys
import os
import pyaiengine

delta = 100
previous_fragments = 0
previous_ip_packets = 0

def timer_5seconds():

    global delta
    global previous_fragments
    global previous_ip_packets

    ipstats = st.get_counters("IP")

    current_ip_packets = ipstats["packets"]
    current_fragmented = ipstats["fragmented packets"]

    print("\033[34m" + "INFO: " + str(ipstats) + "\033[0m")

    if (current_fragmented  > previous_fragments + delta):
        print("\033[31m" + "ALERT: IP Fragment attack on the network" + "\033[0m")

    previous_ip_packets = current_ip_packets
    previous_fragments = current_fragmented

if __name__ == '__main__':

    st = pyaiengine.StackLan()

    st.tcp_flows = 327680
    st.udp_flows = 163840

    source = "enp0s31f6"

    with pyaiengine.PacketDispatcher(source) as pd:
        pd.stack = st
        pd.add_timer(timer_5seconds, 5)        
        pd.run()

    sys.exit(0)

