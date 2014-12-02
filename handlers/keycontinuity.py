from handlers import handlers
from handlers import handler
from db.database import Database
from notification.event_notification import MITMNotification
from handlers.base import BaseHandler
from conf import config, debug_logger
import logging


logger = logging.getLogger(__name__)


@handler(handlers, isHandler=config.V_KEYCONTINUITY)
class KeyContinuity(BaseHandler):

    name = "keycontinuity"
    cert = True
    ocsp = False

    def on_certificate(self, cert):
        hash_t = cert.hash_spki()
        name = cert.subject_common_name()
        algorithm = cert.get_cert_nss().subject_public_key_info.algorithm
        algorithm = algorithm.id_str
        _id = algorithm + ' - ' + name
        exist = db.get(_id)
        if exist is None:
            # That means that the certificate is not in the db, it's the
            # first time it was seen
            db.set_pin(hash_t, _id)
            debug_logger.debug("\t[+] Certificate %s first seen" % name)
        else:
            # Exist so we have to ensure that it is correct
            correct = db.compare(_id, hash_t)
            if correct is False:
                before = db.get(_id)
                debug_logger.debug("\t[-] Certificate %s has changed" % name)
                logger.info(
                    "\t[-] Certificate {0} has changed from".format(name) +
                    " \n{0}--->{1}\n ".format(before["_id"], before["hash"]) +
                    "to \n{0}--->{1}".format(algorithm, hash_t))
                MITMNotification.notify(title=self.name, message=name)
            else:
                debug_logger.debug(
                    "\t[+] Certificate %s has not changed" % name)

# This db is shared by all the instance of Pinning. It is not necessary
# create an instance each time that we use this class.
db = Database(config.DB_NAME, KeyContinuity.name)


