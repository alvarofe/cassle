from handlers import handlers
from handlers import handler
from conf import config, debug_logger
from handlers.base import BaseHandler
from db.database import Database
import logging
from notification.event_notification import MITMNotification
import sys

logger = logging.getLogger(__name__)


@handler(handlers, isHandler=config.V_PINNING)
class Pinning(BaseHandler):

    name = "pinning"
    cert = True
    ocsp = False

    def on_certificate(self, cert):
        name = cert.subject_common_name()
        issuer_name = cert.issuer_common_name()
        try:
            spki = cert.hash_spki(1)
        except:
            logger.error("Getting spki of the intermediate CA %s" % name)
            return
        issuers = db.get(name)
        if issuers is None:
            debug_logger.debug(
                "\t[-] You have not pinned this certificate %s" % name)
            return
        try:
            issuers = issuers["issuers"]
            for i in issuers[issuer_name]:
                if spki == i:
                    debug_logger.debug("\t[+] pin correct %s " % name)
                    return
            logger.info("\t[-] Pin does not match %s" % name)
            debug_logger.debug("\t[-] Pin does not match %s" % name)
            MITMNotification.notify(
                title="pinning",
                message=cert.subject_common_name())
        except:
            debug_logger.debug("\t[-] %s" % sys.exc_info()[0])


db = Database(config.DB_NAME, "pinning")

