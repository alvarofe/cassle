from handlers import handlers
from handlers import handler
from notification.event_notification import MITMNotification
import dns
from dns import resolver
from config import config
from handlers.base import BaseHandler


@handler(handlers,handler=True)
class Icsi(BaseHandler):

    name = "icsi"
    cert = True
    ocsp = False

    def on_certificate(self,cert):
        address = cert.hash()+'.notary.icsi.berkeley.edu'
        name = cert.ca_name()
        try:
            result = resolver.query(address,rdtype=dns.rdatatype.TXT)[0].__str__().split()
        except:
            print "\t[-] Certificate %s isn't in icsi notary" % name
            return
        validated = int(result[4].split('=')[1][0])
        first_seen = int(result[1].split('=')[1])
        last_seen = int(result[2].split('=')[1])
        times_seen = int(result[3].split('=')[1])
        if validated is not 1:
            print "\t[-] Certificate %s is not safe through icsi notary"
            MITMNotification.notify(title="ICSI",message=cert.subject_common_name())
        else:
            s = last_seen - first_seen  + 1
            if s - times_seen >= config.ICSI_MAXIMUM_INTERVAL:
                print "\t[-] Certificate %s is not enough secure acording with icsi notary" % name
                MITMNotification.notify(title='ICSI', message = cert.subject_common_name())
            else:
                print "\t[+] Certificate %s is secure through icsi notary" % name



