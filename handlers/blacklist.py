from handlers import handlers
from handlers import handler
from notification.event_notification import MITMNotification
from db.database import Database
from config import config
from handlers.base import BaseHandler


@handler(handlers,handler=True)
class Blacklist(BaseHandler):

    name = "blacklist"
    cert = True
    ocsp = False

    def on_certificate(self,cert):
        name = cert.ca_name()
        fingerprint = cert.hash()
        query = db.get(fingerprint)
        if query == None:
            print "\t[+] Certificate %s is safe against blacklist" % name
        else:
            print "\t[-] Certificate %s match with a malware site" % name
            MITMNotification.notify(title=self.name,message=cert.subject_common_name())

db = Database(config.DB_NAME, Blacklist.name)
