
from handlers import handlers
from handlers import handler
from notification.event_notification import MITMNotification
from tls import nssconfig
import nss.nss as nss
from nss.error import NSPRError
from handlers.base import BaseHandler
from conf import config, debug_logger
import logging

intended_usage = nss.certificateUsageSSLServer


logger = logging.getLogger(__name__)


@handler(handlers, isHandler=config.V_RFC)
class Rfcnss(BaseHandler):

    name = "rfcnss"

    def __init__(self, cert, ocsp):
        super(Rfcnss, self).__init__(cert, ocsp)
        self.on_certificate(cert)

    def on_certificate(self, cert):
        approved_usage = not intended_usage
        try:
            length = cert.length_chain()
            if length > 4:
                debug_logger.debug(
                    "\t[-] Certificate chain large > 4." +
                    "It's a weird situtation")
                MITMNotification.notify(
                    title="chain large",
                    message=cert.subject_common_name(),
                    group="NSS"
                    )
                return
            cert_nss = cert.get_cert_nss()
            name = cert.ca_name()
            certdb = nssconfig.certdb

            approved_usage = cert_nss.verify_now(
                certdb, True, intended_usage, None)
        except NSPRError:
            cert.add_to_nssdb(cert_nss.issuer.common_name, deep=1)
            if length == 4:
                inter = cert.get_cert_nss(deep=1)
                cert.add_to_nssdb(inter.issuer.common_name, deep=2)
            try:
                approved_usage = cert_nss.verify_now(
                    certdb, True, intended_usage, None)
            except NSPRError:
                pass

        if approved_usage & intended_usage:
            debug_logger.debug(
                "\t[+] Certificate %s is safe using NSS library" % name)
        else:
            debug_logger.debug(
                "\t[-] Certificate %s is not safe using NSS library" % name)
            logger.info(
                "\t[-] Certificate %s is not safe using NSS library" % name)
            MITMNotification.notify(
                title="Chain of trust",
                message=cert.subject_common_name())


