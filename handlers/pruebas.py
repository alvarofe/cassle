from handlers import handlers
from handlers import handler
from handlers.base import BaseHandler
import logging
from pyasn1.codec.der import decoder
from pyasn1_modules import rfc2459
from pyasn1.type import univ
from pyx509.pkcs7_models import X509Certificate
from pyx509.pkcs7.asn1_models.decoder_workarounds import decode
from pyx509.pkcs7.asn1_models.X509_certificate import Certificate



# Clone stock DER decoder and replace its boolean handler so that it permits
# BER encoding of boolean (i.e. 0 => False, anything else => True).
# According to spec, CER/DER should only accept 0 as False and 0xFF as True.
# Though some authors of X.509-cert-creating software didn't get the memo.

logger = logging.getLogger(__name__)


@handler(handlers, isHandler=True)
class Prueba(BaseHandler):

    name = "prueba"

    def __init__(self, cert, ocsp):
        super(Prueba, self).__init__()
        self.on_certificate(cert)

    def on_certificate(self, cert):
        cert, _ = decode(cert.der_data(), Certificate())
#        tbs = cert.getComponentByName('tbsCertificate')
        #extensions = tbs.getComponentByName('extensions')

        #for ext in extensions:
            #if ext.getComponentByPosition(0) == univ.ObjectIdentifier((2,5,29,17)):
                #aux = decoder.decode(ext.getComponentByPosition(2),asn1Spec=rfc2459.GeneralNames())
        certi = X509Certificate(cert)
        tbs = certi.tbsCertificate

        if tbs.subjAltNameExt:
            san = tbs.subjAltNameExt.value
            print "\n".join(san.names)


