from handlers import handlers
from handlers import handler
from notification.event_notification import MITMNotification
from tls import nssconfig
import nss.nss as nss
from nss.error import NSPRError
from handlers.base import BaseHandler

intended_usage = nss.certificateUsageSSLServer


@handler(handlers,handler=True)
class Rfcnss(BaseHandler):

    name = "rfcnss"
    cert = True
    ocsp = False

    def on_certificate(self,cert):
        approved_usage = not intended_usage
        try:
            length = cert.length_chain()
            if length > 4:
                print "\t[-] Certificate chain large > 4. It's a weird situtation"
                MITMNotification.notify(title="chain large",message=cert.subject_common_name())
                return
            cert_nss = cert.get_cert_nss()
            name = cert.ca_name()
            certdb = nssconfig.certdb

            approved_usage = cert_nss.verify_now(certdb,True,intended_usage,None)
        except NSPRError:
            cert.add_to_nssdb(cert_nss.issuer.common_name,deep=1)
            if length == 4:
                inter = cert.get_cert_nss(deep=1)
                cert.add_to_nssdb(inter.issuer.common_name,deep=2)
            try:
                approved_usage = cert_nss.verify_now(certdb,True,intended_usage,None)
            except NSPRError:
                pass

        if approved_usage & intended_usage:
            print "\t[+] Certificate %s is safe using NSS library" % name
        else:
            print "\t[-] Certificate %s is not safe using NSS library" % name
            MITMNotification.notify(title=self.name,message=cert.subject_common_name())
