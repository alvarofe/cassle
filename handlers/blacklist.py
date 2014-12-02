from handlers import handlers
from handlers import handler
from notification.event_notification import MITMNotification
from db.database import Database
from handlers.base import BaseHandler
from conf import config, debug_logger
import logging


logger = logging.getLogger(__name__)


@handler(handlers, isHandler=config.V_BLACKLIST)
class Blacklist(BaseHandler):

    name = "blacklist"
    cert = True
    ocsp = False

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
                "\t[-] Certificate %s match with a malware site" % name
                )
            logger.info(
                "\t[-] Certificate %s match with a malware site" % name
                )
            MITMNotification.notify(
                title=self.name,
                message=cert.subject_common_name()
                )

db = Database(config.DB_NAME, Blacklist.name)


