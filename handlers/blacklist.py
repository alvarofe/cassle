from handlers import handlers
from handlers import handler
from notification.event_notification import MITMNotification
from db.database import BlackListDB
from handlers.base import BaseHandler
from conf import config, debug_logger
import logging


logger = logging.getLogger(__name__)


@handler(handlers, isHandler=config.V_BLACKLIST)
class Blacklist(BaseHandler):

    name = "blacklist"

    def __init__(self, cert, ocsp):
        super(Blacklist, self).__init__(cert, ocsp)
        self.on_certificate(cert)

    def on_certificate(self, cert):
        name = cert.ca_name()
        fingerprint = cert.hash()
        query = db.get(fingerprint)
        if query is None:
            debug_logger.debug(
                "\t[+] Certificate %s is safe against blacklist" % name
                )
        else:
            debug_logger.debug(
                "\t[-] Certificate %s matched with a malware site" % name
                )
            logger.info(
                "\t[-] Certificate %s matched with a malware site" % name
                )
            MITMNotification.notify(
                title=self.name,
                message=cert.subject_common_name())

db = BlackListDB(config.DB_NAME, Blacklist.name)


