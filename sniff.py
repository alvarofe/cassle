#! /usr/bin/env python

############################################################################################### 
### Name: sniff.py
### Author: Alvaro Felipe Melchor - alvaro.felipe91@gmail.com
### Twitter : @alvaro_fe
### University of Alcala de Henares 
###############################################################################################

import sys
import pcap
import argparse
from utils.util import decode_packet
import threading
import os


# TODO add configuration file a clean code




class sniff:
    def __init__(self):
        parser = argparse.ArgumentParser(description='Certificate Validation')
        parser.add_argument('-i','--interface',help='specify interface to sniff')
        parser.set_defaults(interface='en0')
        options = parser.parse_args()
        if options.interface == None:
            print parser.usage
            sys.exit(0)

        self.interface = options.interface

    def handler_signal_term(signum,frame):
        print '%s' % sys.exc_type
        print 'shutting down'

    def sniff(self):
        p = pcap.pcapObject()
        dev = self.interface
        net, mask = pcap.lookupnet(dev)
        p.open_live(dev, 1600, 0, 100)
        p.setfilter("tcp src port 443", 0, 0)
        # print 'The nss database is %s' % (self.db_name)
        #signal.signal(signal.SIGTERM,self.handler_signal_term)
        try:
            while 1:
                p.dispatch(1, decode_packet)
        except KeyboardInterrupt:
            print '%s' % sys.exc_type
            print 'shutting down'
            print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()


def init_ssl_blacklist():
    import wget
    import csv
    from db.database import  database
    fingerprints = list()
    file = wget.download('https://sslbl.abuse.ch/blacklist/sslblacklist.csv',out='/tmp',bar=None)
    with open(file, 'rb') as csvfile:
        reader  = csv.reader(csvfile, delimiter=' ', quotechar='|')
        for row in reader:
            try:
                fingerprints.append(row[1].split(',')[1])
            except:
                pass
    db = database("pfc", "blacklist")
    db.set_black_list(fingerprints)
    os.remove(file) 



if __name__ == '__main__':
    ssl_blacklist = threading.Thread(target=init_ssl_blacklist)
    ssl_blacklist.start()
    s = sniff()
    s.sniff()
