from handlers import handlers
from handlers import handler
from handlers.base import BaseHandler
from conf import config, debug_logger
import logging
from pyasn1.codec.ber import decoder
from utils.sct_deser import DeserializeSCTList, DeserializeSCT
from datetime import datetime
import time
from notification.event_notification import MITMNotification


logger = logging.getLogger(__name__)


@handler(handlers, isHandler=config.V_CT)
class CT(BaseHandler):

    name = "ct"

    def __init__(self, cert, ocsp):
        super(CT, self).__init__(cert, ocsp)
        self._process_ocsp = False
        self._ca_name = ''
        self.on_certificate(cert)

    def check_sct(self, sct):
        sct = decoder.decode(sct)[0]
        sct = str(decoder.decode(str(sct))[0])
        now = datetime.utcnow()
        seconds_from = (now - datetime(1970, 1, 1)).total_seconds()

        sct_list_des = DeserializeSCTList(sct)
        list_sct = sct_list_des.deserialize_sct_list()
        for i in list_sct:
            sct = DeserializeSCT(i).deserialize_sct()
            if seconds_from > sct.timestamp:
                debug_logger.debug(
                    "\t[+] SCT valid found: Version" +
                    " = {0}, LogID = {1}, utc = {2}".format(
                        sct.version, sct.logID, time.ctime(sct.timestamp)))
            else:
                debug_logger.debug(
                    "\t[-] SCT not valid. Timestamp" +
                    " in the future")
                MITMNotification.notify(
                    title="CT", message="SCT in the future")

    def on_certificate(self, cert):
        sct = cert.get_ct_extension()
        if sct is not None:
            self.check_sct(sct)
        else:
            self.on_ocsp_response(self._ocsp)
            self._ca_name = cert.ca_name()

    def on_ocsp_response(self, ocsp):
        sct = ocsp.check_certificate_transparency()
        if sct is not None:
            self.check_sct(sct)
        else:
            debug_logger.debug(
                "\t[-] Certificate %s has not SCT" % self._ca_name)


