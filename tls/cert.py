import nss.nss as nss
from config import config
import os
import hashlib
from Crypto.Util.asn1 import DerSequence
import sha3
import tempfile, subprocess
import M2Crypto.X509
from M2Crypto.X509 import FORMAT_DER
from  pyasn1.codec.der import decoder
from pyasn1_modules import  rfc2459
from pyasn1.type import univ
#To parse the certificate we will use differents frameworks like nss and M2Crypto

class Certificate():
    """docstring for Certificate"""

    def __init__(self, certs):
        """docstring for __init__"""
        self._certs_der = certs

        #configure nss
        self._certdb_dir = os.path.expanduser(config.NSS_DB_DIR)
        nss.nss_init(self._certdb_dir)
        nss.enable_ocsp_checking()
        self._certdb = nss.get_default_certdb()

        self._certs_nss = list()

        for i in xrange(0,len(self._certs_der)):
            try:
                self._certs_nss.append(nss.Certificate(self._certs_der[i],self._certdb))
            except:
                break

    def deep(self):
        """docstring for deep"""
        return len(self._certs_der)

    def _fingerprint(self,data,algorithm="sha1"):
        try:
            fingerprint = hashlib.new(algorithm)
        except:
            print "Algorithm not supported. It'll be used sha1"
            fingerprint = hashlib.new("sha1")
        fingerprint.update(data)
        return fingerprint.hexdigest()

    def hash(self,algorithm="sha1"):
        """
        This method return the hash of the first certificate in the chain with the algorithm
        specified
        """
        return self._fingerprint(self._certs_der[0],algorithm)

    def ca_name(self,deep=0):
        """
        This method return the make_ca_nickname of the certificate specified with the deep parameter
        """
        return self._certs_nss[deep].make_ca_nickname()

    def subject_public_key_info(self):
        """
        This method extract the SubjectPublicKeyInfo from the certificate
        """
        der = self._certs_der[0]
        cert_dec = DerSequence()
        cert_dec.decode(der)
        tbsCertificate = DerSequence()
        tbsCertificate.decode(cert_dec[0])
        spki = tbsCertificate[6]
        return spki

    def hash_spki(self,algorithm="sha3_512"):
        """
        Return the hash of spki using the algorithm specified
        """
        spki = self.subject_public_key_info()
        return self._fingerprint(spki,algorithm)

    def serial_number(self,deep=0):
        try:
            n = self._certs_nss[deep].serial_number
        except:
            n = self._certs_nss[0].serial_number
        return n

    def issuer_common_name(self, deep=0):
        """docstring for issuer_common_name"""
        return self._certs_nss[deep].issuer.common_name


    def add_to_nssdb(self, name, deep=0):
        """docstring for add_to_nssdb"""
        if not os.path.exists(os.getcwd() +'/tmp'):
            os.mkdir(os.getcwd() + '/tmp')

        with tempfile.NamedTemporaryFile(dir=os.getcwd() +'/tmp',suffix='crt') as tmp:
            try:
                tmp.write(M2Crypto.X509.load_cert_string(self.certs[deep],FORMAT_DER).as_pem())
            except:
                return
            tmp.flush
            tmp.seek(0)
            subprocess.call(["certutil", "-A","-n",name,'-t',',,,','-a','-i',tmp.name,'-d',self.certdb_dir])
        return

    def get_ct_extension(self,deep=0):
        """docstring for get_extensions"""
        cert, _ = decoder.decode(self._certs_der[0],asn1Spec=rfc2459.Certificate())
        tbsCertificate = cert.getComponentByName('tbsCertificate')
        extensions =  tbsCertificate.getComponentByName('extensions')
        sct = None
        for ext in extensions:
            if ext.getComponentByPosition(0) == univ.ObjectIdentifier((1,3,6,1,4,1,11129,2,4,2)):
                sct =  str(ext.getComponentByPosition(2))

        return sct

    def subject_common_name(self,deep=0):
        """docstring for subject_common_name"""
        return self._certs_nss[0].subject_common_name

    def get_cert_nss(self,deep=0):
        """docstring for get_cert_nss"""
        try:
            return self._certs_nss[deep]
        except:
            print len(self._certs_nss)
            return self._certs_nss[0]


    def get_cert_der(self,deep=0):
        """docstring for get_cert_der"""
        try:
            return self._certs_der[deep]
        except:
            return self._certs_der[0]

    def get_nssdb(self):
        ""","""
        return self._certdb






