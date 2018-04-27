#!/usr/bin/env python

""" Example for detect SSH abuse on the network """

import sys
import os
import pyaiengine

def timer_5seconds():

    """ Get all the connections that are SSH """
    ssh_connections = [ f for f in st.tcp_flow_manager if f.l7_protocol_name == "SSHProtocol" ]

    con = dict()

    for f in ssh_connections:
        """ Normally connections between 4000 and 3000 encrypted bytes are fail logins """
        if (4000 > f.ssh_info.encrypted_bytes > 3000):
            """ Store the source IP address of the SSH connection """
            if (f.src_ip not in con):
                con[f.src_ip] = 0

            con[f.src_ip] += 1

    """ Check the IPs that have been abuse """
    for k, v in con.iteritems():
        if (v > 5):
            print("\033[31m" + "ALERT: IP %s is brutting force the SSH service" % k + "\033[0m")

if __name__ == '__main__':

    st = pyaiengine.StackLan()

    st.tcp_flows = 327680
    st.udp_flows = 163840

    source = "eth0"

    with pyaiengine.PacketDispatcher(source) as pd:
        pd.stack = st
        pd.add_timer(timer_5seconds, 5)        
        pd.run()

    sys.exit(0)

