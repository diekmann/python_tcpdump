#!/usr/bin/env python

import sys
import re

def handle_IPv4(srcIP, dstIP):
    print "IPv4: %s > %s" % (srcIP, dstIP)
    
def handle_IPv6(srcIP, dstIP):
    print "IPv6: %s > %s" % (srcIP, dstIP)

def main():
    print "cheapIDS starting"
    print """feed me "tcpdump -nn" (via pipe)"""
    
    reTimestamp = r"""\d{2}:\d{2}:\d{0,3}\.\d{0,6} #timestamp"""
    reIPv4 = r"""(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"""
    reIPv6 = r"""(?:[0-9a-f]{1,4}::?){0,7}(?:[0-9a-f]{1,4})?"""
    reMAC = r"""(?:[0-9a-f]{2}:?){6}"""
    
    reTcpdumpIPv4 = re.compile("^"+reTimestamp+r"""
        \ 
        IP #ipv4
        \ 
        ("""+reIPv4+""") #scrIP 
        (?:\.\d{0,5})? #port
        \ > \  
        ("""+reIPv4+""") #dstIP 
        (?:\.\d{0,5})? #port
        : .*
        $""", re.X)
        
    reTcpdumpIPv6 = re.compile("^"+reTimestamp+r"""
        \ 
        IP6 #ipv6
        \ 
        ("""+reIPv6+""") #scrIP 
        (?:\.\d{0,5})? #port
        \ > \  
        ("""+reIPv6+""") #dstIP 
        (?:\.\d{0,5})? #port
        : .*
        $""", re.X)
     
    reTcpdumpARP = re.compile("^"+reTimestamp+r"""
    \ 
    ARP,
    \ .*$""", re.X)
    
    #18:31:38.663388 00:30:1b:bd:26:0f > ff:ff:ff:ff:ff:ff, ethertype Unknown (0x88e1), length 60: 
    reTcpdumpIGNORE = re.compile(r"""^
    (?:\	0x[0-9a-f]{4}:\ \ [0-9a-f]{4}\ .*$) # hex dump of unknown ether type
    |
    (?:
    """+reTimestamp+r"""
    \  
    """+reMAC+r"""\ >\ """+reMAC+r"""
    ,\ ethertype\ Unknown\ \((?:
        (?:0x88e1) # HomePlug AV MME
        |
        (?:0x887b)  # HomePlug 1.0 MME
    )\).* #unknown ether types
    )
    """, re.X)
    
    #print reTcpdumpIGNORE.pattern
    
    while True:
        x = sys.stdin.readline()
        matchIPv4 = re.match(reTcpdumpIPv4, x)
        matchIPv6 = re.match(reTcpdumpIPv6, x)
        matchARP = re.match(reTcpdumpARP, x)
        if matchIPv4:
            srcIP = matchIPv4.group(1)
            dstIP = matchIPv4.group(2)
            handle_IPv4(srcIP, dstIP)
        elif matchIPv6:
            srcIP = matchIPv6.group(1)
            dstIP = matchIPv6.group(2)
            handle_IPv6(srcIP, dstIP)
        elif matchARP:
            #print "ARP request (ignored): %s" % matchARP.group(0)
            pass
        else:
            matchIGNORE = re.match(reTcpdumpIGNORE, x)
            if matchIGNORE:
                #print "ignore: %s" % matchIGNORE.group()
                pass
            else:
                print "Unmatched input: %s" % x


main()

