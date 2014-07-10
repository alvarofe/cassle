###############################################################################################
### Name: auth_certificate.py
### Author: Alvaro Felipe Melchor - alvaro.felipe91@gmail.com
### Twitter : @alvaro_fe
### University of Alcala de Henares
###############################################################################################



#Here all related with the verification through certficate

#from utils import util
import M2Crypto.X509
from M2Crypto.X509 import FORMAT_DER

import logging
from ssl import ssl_types
import threading
import nss.nss as nss
import os
import platform
from pync import Notifier
from termcolor import colored
from db.database import database

from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2560, rfc2459, pem
from pyasn1.type import univ




from config import Config

#Configuration stuff
f = file('config/config.cfg')
cfg = Config(f)
f.close()
#


########      LOG     #########
LOGFILENAME = 'cert.log'
LOG_DIR = cfg.config.LOG_DIR
try:
    os.mkdir(os.path.expanduser(LOG_DIR))
except OSError:
    # This error means that the directoy exists
    pass
logPath = os.path.expanduser(LOG_DIR) + LOGFILENAME
logging.basicConfig(filename=logPath,format='%(asctime)s --  %(levelname)s:%(message)s', level=logging.INFO)
########      LOG     #########


system = platform.system()

class AuthCertificate(threading.Thread):
    """
    This class validate the authentication through certificate
    """

    def __init__(self, certificate_message,queue, screen_lock):

        #The queue is used to return data to the main thread
        threading.Thread.__init__(self)
        self.lock = screen_lock
        self.queue= queue
        self.cert_message = certificate_message
        self._get_certificate_chain()

        certdb = os.path.expanduser(cfg.config.NSS_DB_DIR)

        nss.nss_init(certdb)
        self.certdb = nss.get_default_certdb()

        db_name = cfg.db.db_name
        self.db_pin = database(db_name, cfg.db.coll_name_pinning)
        self.db_rfc = database(db_name, cfg.db.coll_name_log)

        self._print_first_certificate_of_chain()

    def run(self):
        pass
        #TODO add here execution based on the configuration file
        #self.verify_cert_with_pinning()
        #self.verify_cert_with_icsy_notary()

    """
    Methods that implement verification using the certificate
    """
    def verify_cert_through_rfc(self):
        #TODO implement this latter
        pass

    def verify_cert_with_pinning(self):
        import hashlib
        from Crypto.Util.asn1 import DerSequence
        import sha3
        s = hashlib.new("sha3_512")
        try:
            # We extract SubjectPublicKeyInfo. Why? Because everybody say that is the best part of the certificate
            #to do that

            der = self.certs[0]
            cert_dec = DerSequence()
            cert_dec.decode(der)
            tbsCertificate = DerSequence()
            tbsCertificate.decode(cert_dec[0])
            spki = tbsCertificate[6]

            s.update(spki)
            hash_t = s.hexdigest()
            cert = nss.Certificate(self.certs[0],self.certdb)
            ca_name = cert.make_ca_nickname()
            exist = self.db_pin.get(ca_name)
            if exist == None:
                # That means that the certificate is not in the database, it's the first time it was seen
                self.db_pin.set_pin(hash_t, ca_name)
                cad = "%s first seen" % ca_name
                self.lock.acquire()
                print colored(cad,'yellow')
                self.lock.release()
            else:
                # Exist so we have to ensure it's correct
                correct = self.db_pin.compare(ca_name, hash_t)
                if correct == False:
                    cad = 'This certificate %s changed' % ca_name
                    self.lock.acquire()
                    print colored(cad,'red')
                    self.lock.release()
                    self._notify_mitm(title=ca_name)

                else:
                    cad = 'Nothing changed ' + ca_name
                    self.lock.acquire()
                    print colored(cad,'yellow')
                    self.lock.release()
        except Exception:
            pass


    def verify_cert_with_icsy_notary(self):
        import hashlib
        import dns
        from dns import resolver
        cert = nss.Certificate(self.certs[0],self.certdb)
        s = hashlib.new("sha1")
        s.update(cert.der_data)
        address = s.hexdigest()+'.notary.icsi.berkeley.edu'
        try:
            result =  resolver.query(address,rdtype=dns.rdatatype.TXT)[0].__str__().split()
        except:
            print 'Timeout raised'
            return
        validated = int(result[4].split('=')[1][0])
        first_seen = int(result[1].split('=')[1])
        last_seen = int(result[2].split('=')[1])
        times_seen = int(result[3].split('=')[1])
        if validated is not 1:
            cad = "This certificate %s is NOT safe through icsi_notary" % (cert.make_ca_nickname())
            self.lock.acquire()
            print colored(cad,'red')
            self.lock.release()
        else:
            s = last_seen - first_seen  + 1
            if s - times_seen > 1:
                cad = "This certificate %s is not ENOUGH secure according to icsi_notary" % (cert.make_ca_nickname())
                self.lock.acquire()
                print colored(cad,'magenta')
                self.lock.release()
            else:
                cad = "This certificate %s IS SECURE through icsi_notary" % (cert.make_ca_nickname())
                self.lock.acquire()
                print colored(cad,'blue')
                self.lock.release()



    def _notify_mitm(self,title):
        if system == "Darwin":
            Notifier.notify("MITM",title=title)
        else:
            pass

    def info_extension_cert(self,cert):
        """
        This function take a certificate and return the extensions in dict.

        @type cert : M2Crypto.X509
        @param cert : Certificate
        """
        certificateExtensions = {}

        for index in range(cert.get_ext_count()):
            ext = cert.get_ext_at(index)
            certificateExtensions[ext.get_name()] = ext.get_value()
        return certificateExtensions

    def _print_first_certificate_of_chain(self):
        import re
        cert = nss.Certificate(self.certs[0],self.certdb)
        cert = M2Crypto.X509.load_cert_string(self.certs[0],FORMAT_DER)
        infos = [x.strip() for x in self.info_extension_cert(cert)["authorityInfoAccess"].split('\n')]
        ocsp_url = None
        for info in infos:
            if re.match(r"^OCSP - URI:", info):
                ocsp_url = info.replace("OCSP - URI:","")
                break
        print ocsp_url.strip()
        #ocsp_oid = univ.ObjectIdentifier((1, 3, 6, 1, 5, 5, 7, 48, 1))
        #print cert.get_extension("SEC_OID_PKIX_OCSP")

    def _get_certificate_chain(self):
        #Once we have all the chain we can validate
        #First of all we need to check if is a handshake_message security reason

        self.certs = list()

        if self.cert_message[0:2] == ssl_types.TLS_HANDSHAKE:
            if self.cert_message[10:12] == ssl_types.TLS_H_TYPE_CERTIFICATE:
                #Basically we need to retrieve all the chain and save it to after do all autenthication
                chain_length = int(self.cert_message[18:24],16)
                certs = self.cert_message[24:]
                total_length = 0
                while True:
                    length = int(certs[0:6],16)
                    total_length += length + 3
                    next_cert = 6 + ( length * 2)
                    self.certs.append(certs[6:next_cert].decode('hex'))
                    if total_length == chain_length:
                        break

                    #FIXME try refactor this
                    try:
                        certs = certs[next_cert:]
                    except:
                        break

