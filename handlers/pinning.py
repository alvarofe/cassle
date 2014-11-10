from handlers import handlers
from handlers import handler
from db.database import Database
from config import config
from notification.event_notification import MITMNotification
from handlers.base import BaseHandler



@handler(handlers,handler=True)
class Pinning(BaseHandler):

    name = "pinning"
    cert = True
    ocsp = False

    def on_certificate(self,cert):
        #db = Database(config.DB_NAME,self.name)
        hash_t = cert.hash_spki()
        serial = cert.serial_number()
        name = cert.ca_name()
        _id = str(serial) + ' - ' + name
        exist = db.get(_id)
        if exist == None:
            #That means that the certificate is not in the db, it's the first time
            #it was seen
            db.set_pin(hash_t,_id)
            print "\t[+] Certificate %s first seen" % name
        else:
            #Exist so we have to ensure that it is correct
            correct = db.compare(_id,hash_t)
            if correct == False:
                print "\t[-] Certificate %s has changed" % name
                MITMNotification(title=self.name,message = cert.subject_common_name())
            else:
                print "\t[+] Certificate %s has not changed" % name


db = Database(config.DB_NAME,Pinning.name)
