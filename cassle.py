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
from multiprocessing import Process
import os
from conf import config
from db.database import PinDB, BlackListDB
from apscheduler.schedulers.background import BackgroundScheduler
from notification.event_notification import MITMNotification
from notification.notification_osx import NotificationOSX
import urllib2
import json
import logging.config


scheduler = BackgroundScheduler()


log_ap = logging.getLogger("apscheduler.scheduler")
log_ap.disabled = 1


def drop():
    db = PinDB(config.DB_NAME, "keycontinuity")
    db.drop_pinning()


class Sniff:
    def __init__(self):
        parser = argparse.ArgumentParser(description='Certificate Validation')
        parser.add_argument(
            '-i',
            '--interface',
            help='specify interface to sniff'
            )
        parser.add_argument(
            '-p',
            '--port',
            help='specify the port to sniff'
            )
        # This default is becuase I am using mac os x .
        # If you use Linux is likely the interface be eth0/1
        parser.set_defaults(interface='en0')
        parser.set_defaults(port='443')
        options = parser.parse_args()
        if options.interface is None:
            print parser.usage
            sys.exit(0)

        self.interface = options.interface
        self.port = options.port

    def sniff(self):
            p = pcap.pcapObject()
            dev = self.interface
            net, mask = pcap.lookupnet(dev)
            p.open_live(dev, 1600, 0, 100)
            p.setfilter("tcp src port %s" % self.port, 0, 0)
            try:
                while 1:
                    p.dispatch(1, decode_packet)
            except KeyboardInterrupt:
                scheduler.shutdown()
                print '%s' % sys.exc_type
                print 'shutting down'
                print '%d packets received, %d packets dropped, %d packets \
                        dropped by interface' % p.stats()


def init_ssl_blacklist():
    """
    This function setup the sslblacklist database with our local database to
    use later in the validation process
    """
    import csv
    fingerprints = list()
    file = urllib2.urlopen('https://sslbl.abuse.ch/blacklist/sslblacklist.csv')
    reader = csv.reader(file, delimiter=' ', quotechar='|')
    for row in reader:
        try:
            fingerprints.append(row[1].split(',')[1])
        except:
            pass
    db = BlackListDB(config.DB_NAME, "blacklist")
    db.set_black_list(fingerprints)
    print '[+] SSL blacklist downloaded'


if __name__ == '__main__':

    # This is to delete the pinning database each day to avoid that an evil
    # site perform MITM attacks over our connections That's why because in our
    # code we save the pinning each time that we visite a site. But if this
    # site is evil we are saving bad pinning so we have to delete the database
    # to ensure that evil site has been deleted. You can change the seconds
    # in the configuration file

    scheduler.add_job(drop, 'interval', seconds=config.DB_TIME_REMOVE)
    scheduler.start()

    # configure logger

    with open(os.path.expanduser(config.LOG_FILE)) as log:
        config_log = json.load(log)
    logging.config.dictConfig(config_log)

    # Configure type of notifications

    if sys.platform == "darwin":
        MITMNotification.register(NotificationOSX())

    print '[+] Downloading SSL blacklist'
    proc = Process(target=init_ssl_blacklist, args=())
    proc.start()
    print '[+] Sniffing'

    s = Sniff()
    s.sniff()

