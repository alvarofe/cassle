from handlers import handlers
from handlers import handler
from notification.event_notification import MITMNotification
from datetime import datetime
import pyasn1.type.useful as useful
from handlers.base import BaseHandler
from conf import config, debug_logger
import logging




logger = logging.getLogger(__name__)



@handler(handlers,handler=config.V_OCSP)
class OCSP(BaseHandler):

    name = "ocsp"
    cert = False
    ocsp = True

    def on_ocsp_response(self,ocsp):
        status,certId,thisUpdate,nextUpdate,serial,name = ocsp.get_response()
        utcnow = datetime.utcnow()
        now = useful.UTCTime(utcnow)
        if status == None:
            debug_logger.debug("\t[-] Certificate has not OCSP URI")
            return
        if certId == serial:
            if status == 'revoked':
                debug_logger.debug("\t[-] Certificate %s revoked" % name)
                logger.info("\t[-] Certificate %s revoked" % name)
                MITMNotification.notify(title=self.name,message=name)
                return
            try:
                check_before = now < useful.UTCTime(thisUpdate)
            except:
                debug_logger.debug("\t[-] This certificate although is NOT revoked does not provide information in thisUpdate")
                return
            try:
                check_after = now < useful.UTCTime(nextUpdate)
            except:
                debug_logger.debug("\t[-] This certificate although is NOT revoked does not provide information in nextUpdate")
                return
            if  check_before and check_after:
                debug_logger.debug("\t[+] Certificate %s is not revoked" % name)
            else:
                debug_logger.debug("\t[-] Likely you are under reply attack with the Certificate %s" % name)
                logger.info("\t[-] Likely you are under reply attack with the Certificate %s" % name)
        else:
            debug_logger.debug("\t[-] Likely you have received a bad response from OCSP responder of %s" %name)
            logger.info("\t[-] Likely you have received a bad response from OCSP responder of %s" %name)
            MITMNotification.notify(title=self.name,message="OCSP bad response")

