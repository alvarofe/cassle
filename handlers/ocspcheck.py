
from handlers import handlers
from handlers import handler
from notification.event_notification import MITMNotification
from datetime import datetime
from handlers.base import BaseHandler
from conf import config, debug_logger
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc2459
import hashlib
import logging
from tls.ocsp import ValueOnlyBitStringEncoder


logger = logging.getLogger(__name__)


@handler(handlers, isHandler=config.V_OCSP)
class OCSP(BaseHandler):

    name = "ocsp"

    def __init__(self, cert, ocsp):
        super(OCSP, self).__init__(cert, ocsp)
        self.valueOnlyBitStringEncoder = ValueOnlyBitStringEncoder()
        self.on_ocsp_response(ocsp)

    def on_ocsp_response(self, ocsp):
        (
            status,
            certId,
            thisUpdate,
            nextUpdate,
            issuerHashz
        ) = ocsp.get_response()
        serial = self._cert.serial_number()

        issuer = self._cert.der_data(1)
        issuer_der = decoder.decode(issuer, asn1Spec=rfc2459.Certificate())[0]
        issuerTbsCert = issuer_der.getComponentByName('tbsCertificate')
        issuerSubjectPublicKey = issuerTbsCert.getComponentByName(
            'subjectPublicKeyInfo').getComponentByName('subjectPublicKey')
        issuerKeyHash = hashlib.sha1(
            self.valueOnlyBitStringEncoder(issuerSubjectPublicKey)
            ).digest()

        name = self._cert.ca_name()

        if status is None:
            debug_logger.debug("\t[-] Certificate has not OCSP URI")
            return

        if status == 3:
            # It is own status code
            debug_logger.debug("\t[-] Not bytes in OCSP response")
            MITMNotification.notify(
                title="OCSP",
                message="No bytes in response")
            return

        if certId == serial and issuerHashz == issuerKeyHash:
            if status == 'revoked':
                debug_logger.debug("\t[-] Certificate %s revoked" % name)
                logger.info("\t[-] Certificate %s revoked" % name)
                MITMNotification.notify(
                    title='OCSP', message=name)
                return

            utcnow = datetime.utcnow()
            try:
                date_thisUpdate = datetime(
                    year=int(thisUpdate[0:4]), month=int(thisUpdate[4:6]),
                    day=int(thisUpdate[6:8]), hour=int(thisUpdate[8:10]),
                    minute=int(thisUpdate[10:12]),
                    second=int(thisUpdate[12:14]))
            except:
                debug_logger.debug(
                    "\t[-] This certificate although is NOT revoked does not"
                    + "provide information in thisUpdate")
                return
            check_thisUpdate = utcnow > date_thisUpdate
            try:
                date_NextUpdate = datetime(
                    year=int(nextUpdate[0:4]), month=int(nextUpdate[4:6]),
                    day=int(nextUpdate[6:8]), hour=int(nextUpdate[8:10]),
                    minute=int(nextUpdate[10:12]),
                    second=int(nextUpdate[12:14]))
                check_NextUpdate = date_NextUpdate > utcnow
                if check_NextUpdate is True:
                    self._check_thisUpdate(check_thisUpdate, name)
                else:
                    debug_logger.debug(
                        "\t[-] There will not be more revocation status" +
                        "information about %s" % name)
            except:
                self._check_thisUpdate(check_thisUpdate, name)
                pass
        else:
            debug_logger.debug(
                "\t[-] Likely you have received a bad response from OCSP" +
                " responder of %s" % name)
            logger.info(
                "\t[-] Likely you have received a bad response from OCSP" +
                " responder of %s" % name)
            MITMNotification.notify(
                title='OCSP',
                message="OCSP bad response")

    def _check_thisUpdate(self, check_thisUpdate, name):
        if check_thisUpdate is True:
            debug_logger.debug(
                "\t[+] Certificate %s is not revoked" % name)
        elif check_thisUpdate is False:
            debug_logger.debug('\t[-] Awkward Situation %s' % name)

