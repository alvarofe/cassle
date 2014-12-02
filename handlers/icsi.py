from handlers import handlers
from handlers import handler
from notification.event_notification import MITMNotification
import dns
from dns import resolver
from conf import config, debug_logger
from handlers.base import BaseHandler
import logging


logger = logging.getLogger(__name__)


@handler(handlers, isHandler=config.V_ICSI)
class Icsi(BaseHandler):

    name = "icsi"
    cert = True
    ocsp = False

    def on_certificate(self, cert):
            address = cert.hash()+'.notary.icsi.berkeley.edu'
            name = cert.ca_name()
            try:
                result = resolver.query(
                    address,
                    rdtype=dns.rdatatype.TXT
                    )[0].__str__().split()
            except:
                debug_logger.debug(
                    "\t[-] Certificate %s isn't in icsi notary" % name
                    )
                return
            validated = int(result[4].split('=')[1][0])
            first_seen = int(result[1].split('=')[1])
            last_seen = int(result[2].split('=')[1])
            times_seen = int(result[3].split('=')[1])
            if validated is not 1:
                debug_logger.debug(
                    "\t[-] Certificate {0}".format(name) +
                    " is not safe through icsi notary")
                logger.info(
                    "\t[-] Certificate {0}".format(name) +
                    "is not safe through icsi notary")
                MITMNotification.notify(
                    title="ICSI",
                    message=cert.subject_common_name())
            else:
                s = last_seen - first_seen + 1
            if s - times_seen >= config.ICSI_MAXIMUM_INTERVAL:
                debug_logger.debug(
                    "\t[-] Certificate {0}".format(name) +
                    " is not enough secure acording with icsi notary")
                MITMNotification.notify(
                    title='ICSI',
                    message=cert.subject_common_name())
            else:
                debug_logger.debug(
                    "\t[+] Certificate %s is secure through icsi notary"
                    % name)



