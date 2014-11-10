#! /usr/bin/env python


# Copyright (C) 2014       Alvaro Felipe Melchor (alvaro.felipe91@gmail.com)


# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import sys
import pcap
import argparse
from utils.util import decode_packet
import threading
import os
from config import config
#import subprocess
from db.database import Database
from apscheduler.schedulers.background import BackgroundScheduler
from notification.event_notification import MITMNotification
from notification.notification_osx import NotificationOSX
#from utils.mail_notification import MailNotification


#from OpenSSL import SSL




scheduler = BackgroundScheduler()

def drop():
    db = Database(config.DB_NAME, "pinning")
    db.drop_pinning()

class Sniff:
    def __init__(self):
        parser = argparse.ArgumentParser(description='Certificate Validation')
        parser.add_argument('-i','--interface',help='specify interface to sniff')
        # This default is becuase I am using mac os x . If you use Linux is likely the interface be eth0/1
        parser.set_defaults(interface='en0')
        options = parser.parse_args()
        if options.interface == None:
            print parser.usage
            sys.exit(0)

        self.interface = options.interface

    def sniff(self):
        global scheduler
        p = pcap.pcapObject()
        dev = self.interface
        net, mask = pcap.lookupnet(dev)
        p.open_live(dev, 1600, 0, 100)
        p.setfilter("tcp src port 443", 0, 0)
        try:
            while 1:
                p.dispatch(1, decode_packet)
        except KeyboardInterrupt:
            scheduler.shutdown()
            print '%s' % sys.exc_type
            print 'shutting down'
            print '%d packets received, %d packets dropped, %d packets dropped by interface' % p.stats()


def init_ssl_blacklist():
    """
    This function setup the sslblaclist database with our local database to use later in the validation process
    """
    import wget
    import csv
    from db.database import  Database
    fingerprints = list()
    file = wget.download('https://sslbl.abuse.ch/blacklist/sslblacklist.csv',out='/tmp/',bar=None)
    with open(file, 'rb') as csvfile:
        reader  = csv.reader(csvfile, delimiter=' ', quotechar='|')
        for row in reader:
            try:
                fingerprints.append(row[1].split(',')[1])
            except:
                pass
    db = Database(config.DB_NAME, "blacklist")
    db.set_black_list(fingerprints)
    os.remove(file)

def stub_verify(conn,cert,errno,errdepth,code):
    return True

if __name__ == '__main__':

    # This is to delete the pinning database each day to avoid that an evil site perform MITM attacks over our connections
    # That's why because in our code we save the pinning each time that we visite a site. But if this site is evil we are saving bad pinning
    # so we have to delete the database to ensure that evil site has been deleted. You can change the seconds in the configuration file


    scheduler.add_job(drop, 'interval', seconds=config.DB_TIME_REMOVE)
    scheduler.start()

    #print '***** launching mongo daemon *****'
    #devnull = open('/dev/null', 'w')
    #try:
        #subprocess.Popen('mongod',stdout=devnull)
    #except:
        #pass
    #print '***** launched mongo daemon *****'

    #Configure type of notifications

    MITMNotification.register(NotificationOSX())
    #MITMNotification.register(MailNotification())

    print '[+] Downloading SSL blacklist'
    init_ssl_blacklist()
    print '[+] SSL blacklist downloaded'
    print '[+] Sniffing'

    s = Sniff()
    s.sniff()
