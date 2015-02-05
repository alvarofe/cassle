from handlers import handlers
from handlers import handler
from conf import config, debug_logger
from handlers.base import BaseHandler
from db.database import PinDB
import logging
from notification.event_notification import MITMNotification
import base64

logger = logging.getLogger(__name__)


@handler(handlers, isHandler=config.V_PINNING)
class Pinning(BaseHandler):

    name = "pinning"

    def __init__(self, cert, ocsp):
        super(Pinning, self).__init__(cert, ocsp)
        self.on_certificate(cert)

    def on_certificate(self, cert):
        name = cert.subject_common_name()
        issuer_name = cert.issuer_common_name()
        query = db.get(name)
        if query is None:
            debug_logger.debug(
                "\t[-] You have not pinned this certificate %s" % name)
            return
        try:
            spki = cert.hash_spki(deep=1, algorithm="sha256")
            spki = base64.b64encode(spki)
        except:
            logger.error("Getting spki of the intermediate CA %s" % name)
            return
        try:
            issuers = query["issuers"]
            for i in issuers[issuer_name]:
                if spki == i:
                    debug_logger.debug("\t[+] pin correct %s " % name)
                    return
            logger.info("\t[-] Pin does not match %s" % name)
            debug_logger.debug("\t[-] Pin does not match %s" % name)
            MITMNotification.notify(
                title="Pinning",
                message=cert.subject_common_name())
        except:
            MITMNotification.notify(
                title="Pinning",
                message="Issuer different")
            debug_logger.debug("\t[-] issuer with different name %s" % name)


db = PinDB(config.DB_NAME, "pinning")


