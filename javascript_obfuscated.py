#!/usr/bin/env python
# Example for detect the javascript that is obfuscated on HTTP
# For example the Aurora exploit CVE-2010-0249
import sys
import pyaiengine
import re

"""
<html>
<head>
<script>

	var HWbNxNSkRllwvJXJeJuqiwKKahyIDpYYRehHiMtXeXsHHHosvYqKGAzZOQLHbFdKbHEbxndl = "COMMENT";

	var iVOBqWOquxKUmAjjvDMGCBYRWuUPGFKnlitoSZZYUdoqbBRaOWCjBglgmrrQFRNqhiLcBLStTILwRGsSUIk = new Array();
	for (i = 0; i < 200; i ++ ){
	   iVOBqWOquxKUmAjjvDMGCBYRWuUPGFKnlitoSZZYUdoqbBRaOWCjBglgmrrQFRNqhiLcBLStTILwRGsSUIk[i] = document.createElement(HWbNxNSkRllwvJXJeJuqiwKKahyIDpYYRehHiMtXeXsHHHosvYqKGAzZOQLHbFdKbHEbxndl);
	   iVOBqWOquxKUmAjjvDMGCBYRWuUPGFKnlitoSZZYUdoqbBRaOWCjBglgmrrQFRNqhiLcBLStTILwRGsSUIk[i].data = "YMI";
	};

	var WqtWkawotcbBKtGJoIStaLldZLjvXJWdpyYOYiWOToceLKverxJpYbwIfrnXZiSeGCiHdhoTrcvPbdgSNuAxeW = null;
"""

def payload_callback(flow):

    print("\033[93m" + "WARNING: Possible JavaScript Attack detected on %s" % str(flow) + "\033[0m")
    text = ''.join(chr(i) for i in flow.payload)

    lengths = 0
    i = 0
    """ We extract the variables definition """
    for match in re.finditer("var.*=", text):
        variable_name = match.group().split(" ")[1]
        lengths = lengths + len(variable_name)
        i += 1

    if (i > 0):
        average = lengths / i
        """ If the average of the variable names is greater than 50 """
        if (average > 50): 
            print("\033[31m" + "ALERT: CVE-2010-0249 Aurora Attack detected on %s" % str(flow) + "\033[0m")

if __name__ == '__main__':

    st = pyaiengine.StackLan()

    dm = pyaiengine.DomainNameManager()
    rm = pyaiengine.RegexManager()
    r = pyaiengine.Regex("Potential JavaScript execution", b"<script>", payload_callback)
    d = pyaiengine.DomainName("All com traffic", "*")

    rm.add_regex(r)

    d.regex_manager = rm

    dm.add_domain_name(d)

    st.set_domain_name_manager(dm, "HTTPProtocol")

    st.set_dynamic_allocated_memory(True)

    source = "EXPLOIT_metasploit_ie_aurora_exploitWin2k3_EvilFingers.pcap"

    with pyaiengine.PacketDispatcher(source) as pd:
        pd.stack = st
        pd.run()

    sys.exit(0)

