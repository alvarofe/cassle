#! /usr/bin/env python

###############################################################################################
### Name: sniff.py
### Author: Alvaro Felipe Melchor - alvaro.felipe91@gmail.com
### Twitter : @alvaro_fe
### University of Alcala de Henares
###############################################################################################


#import os
import sys
import nids
import signal

#from utils import util
from ssl.ssl_stream import SSLStream

NOTROOT = "nobody"   # edit to taste
end_states = (nids.NIDS_CLOSE, nids.NIDS_TIMEOUT, nids.NIDS_RESET)

def signal_handler(signal, frame):
        print('You pressed Ctrl+C!')
        sys.exit(0)

def handleTcpStream(tcp):
    #print "tcps -", str(tcp.addr), " state:", tcp.nids_state>
    if tcp.nids_state == nids.NIDS_JUST_EST:
        # new to us, but do we care?
        ((src, sport), (dst, dport)) = tcp.addr
        #print tcp.addr
        if dport  == 443:
            #print "collecting..."
            tcp.client.collect = 1
            #tcp.server.collect = 1
    elif tcp.nids_state == nids.NIDS_DATA:
        #TODO manage better tcp stream because we are only catching tcp stream when it is closed
        # keep all of the stream's new data
        tcp.discard(0)
    elif tcp.nids_state in end_states:
        #print "addr:", tcp.addr
        #print "To client:"
        #TODO try to have only one instance of this class and only a set method to put inside the message to trigger all the process
        SSLStream(tcp.client.data[:tcp.client.count],tcp.addr)
        #tcp.client.collect = 0
        #print util.hexdump(tcp.client.data[:tcp.client.count])
        #print tcp.client.data[:tcp.client.count] # WARNING - as above

def main():

    #nids.param("pcap_filter", "tcp")       # bpf restrict to TCP only, note
                                            # libnids caution about fragments
    signal.signal(signal.SIGINT, signal_handler)
    #nids.param("scan_num_hosts", 0)         # disable portscan detection

    #if len(sys.argv) == 2:                  # read a pcap file?
        #nids.param("filename", sys.argv[1])

    nids.init()

    nids.register_tcp(handleTcpStream)
    #print "pid", os.getpid()

    # Loop forever (network device), or until EOF (pcap file)
    # Note that an exception in the callback will break the loop!
    try:
        nids.run()
    except nids.error, e:
        print "nids/pcap error:", e
    #except Exception,e:
        #print "misc. exception (runtime error in user callback?):", e

if __name__ == '__main__':
    main()
