#!/usr/bin/env python

""" Example for spam detectin by using SPF query records 
    Needs pyspf for do the SPF check 
"""

import sys
import os
import pyaiengine
import spf

def spf_callback(flow):

    from_to = flow.smtp_info.mail_from
    if (from_to):
        print(spf.check(i=flow.src_ip, s=from_to, h="8.8.8.8"))

if __name__ == '__main__':

    st = pyaiengine.StackLan()

    dm = pyaiengine.DomainNameManager()
    d = pyaiengine.DomainName("All .com domains" ,".com", spf_callback)

    dm.add_domain_name(d)

    """ Plug the DomainNameManager on the SMTPProtocol """ 
    st.set_domain_name_manager(dm, "SMTPProtocol")

    st.tcp_flows = 50000
    st.udp_flows = 16380

    source = "eth0"

    with pyaiengine.PacketDispatcher(source) as pd:
        pd.stack = st
        pd.run()

    sys.exit(0)

