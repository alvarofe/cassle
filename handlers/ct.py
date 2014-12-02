from handlers import handlers
from handlers import handler
from handlers.base import BaseHandler
from conf import config, debug_logger
import logging
from pyasn1.codec.ber import decoder
from utils.sct_deser import DeserializeSCTList, DeserializeSCT
from datetime import datetime
import time


logger = logging.getLogger(__name__)


@handler(handlers, isHandler=config.V_CT)
class CT(BaseHandler):

    name = "ct"
    cert = True
    ocsp = True

    def __init__(self):
        self._process_ocsp = False
        self._lock = False
        self._ca_name = ''

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

    def on_certificate(self, cert):
        sct = cert.get_ct_extension()
        if sct is not None:
            self.check_sct(sct)
            # debug_logger.debug(
            # "\t[+] Certificate %s has SCT %s"
            # % (cert.ca_name(), sct.encode('hex')))
        else:
            self._process_ocsp = True
            self._ca_name = cert.ca_name()
        self._lock = True

    def on_ocsp_response(self, ocsp):
        while self._lock is False:
            pass
        if self._process_ocsp is True:
            sct = ocsp.check_certificate_transparency()
            if sct is not None:
                self.check_sct(sct)
                # debug_logger.debug(
                # "\t[+] Certificate %s has SCT %s" %
                # (self._ca_name, sct.encode('hex')))
            else:
                debug_logger.debug(
                    "\t[-] Certificate %s has not SCT" % self._ca_name)



