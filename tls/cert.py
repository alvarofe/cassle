import nss.nss as nss
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
from tls import nssconfig
#To parse the certificate we will use differents frameworks like nss and M2Crypto

#TODO improve the code of this file to catch error and propagate

class X509Chain():

  """It's a wrap to the class nss.Certificate but dealing with a chain
  All the methods have in common a parameter "deep" that indicate which certificate
  in the chain have you applying the method"""

  def __init__(self, certs):
    """docstring for __init__"""
    self._certs_der = certs
    self._certs_nss = list()

    for i in xrange(0, len(self._certs_der)):
      try:
        self._certs_nss.append(nss.Certificate(self._certs_der[i],nssconfig.certdb))
      except:
        break


  def length_chain(self):
    """To know the length of the chain"""
    return len(self._certs_der)

  def _fingerprint(self,data,algorithm="sha1"):
    """ Method private to hash data

    data: data to hash
    algorithm : algorithm to use
    """
    try:
      fingerprint = hashlib.new(algorithm)
    except:
      raise Exception("Algorithm not supported _fingerprint method")
    fingerprint.update(data)
    return fingerprint.hexdigest()

  def hash(self, deep=0,algorithm="sha1"):
    """
    This method return the hash of the certificate in the chain with the algorithm specified

    deep : Which certificate in the chain you want
    algorithm : string that represent the algorithm to use
    """
    return self._fingerprint(self._certs_der[deep],algorithm)

  def ca_name(self, deep=0):
    """
    This method return the make_ca_nickname of the certificate.

    deep : Which certificate in the chain you want to obtain the ca_name
    """
    try:
      return self._certs_nss[deep].make_ca_nickname()
    except:
      raise Exception("List index out of range in ca_name")

  def subject_public_key_info(self,deep=0):
    """
    This method extract the SubjectPublicKeyInfo from the certificate and return it as der
    """
    try:
      der = self._certs_der[deep]
      cert_dec = DerSequence()
      cert_dec.decode(der)
      tbsCertificate = DerSequence()
      tbsCertificate.decode(cert_dec[0])
      spki = tbsCertificate[6]
      return spki
    except:
      raise Exception("subject_public_key_info issue")

  def hash_spki(self,deep=0,algorithm="sha3_512"):
    """
    Return the hash of spki using the algorithm specified

    algorithm: Algorithm to hash the spki
    """
    spki = self.subject_public_key_info(deep)
    return self._fingerprint(spki,algorithm)

  def serial_number(self,deep=0):
    """
    Certificate's serial number
    """
    try:
      n = self._certs_nss[deep].serial_number
      return n
    except:
      raise Exception("serial_number")

  def issuer_common_name(self, deep=0):
    """Certificate's issuer name

    deep : Which certificate you want to know the issuer name
    """
    try:
      return self._certs_nss[deep].issuer.common_name
    except:
      raise Exception("issuer_common_name")


  def add_to_nssdb(self, name, deep=0):
    """Add certificate to the nssdb to authenticate. You add it to verify but you don't trust in this certificate

    deep: Which certificate you want to save in the db
    """
    if not os.path.exists(os.getcwd() +'/tmp'):
      os.mkdir(os.getcwd() + '/tmp')

    with tempfile.NamedTemporaryFile(dir=os.getcwd() +'/tmp', suffix='crt') as tmp:
      try:
        tmp.write(M2Crypto.X509.load_cert_string(self._certs_der[deep],FORMAT_DER).as_pem())
      except:
        return
      tmp.flush()
      tmp.seek(0)
      subprocess.call(["certutil", "-A", "-n",name, '-t', ',,,', '-a', '-i', tmp.name,'-d', nssconfig.certdb_dir])
    return

  def get_ct_extension(self,deep=0):
    """Get the Certificate Transparency Extension from Certificate"""
    cert, _ = decoder.decode(self._certs_der[deep], asn1Spec=rfc2459.Certificate())
    tbsCertificate = cert.getComponentByName('tbsCertificate')
    extensions =  tbsCertificate.getComponentByName('extensions')
    sct = None
    for ext in extensions:
      if ext.getComponentByPosition(0) == univ.ObjectIdentifier((1,3,6,1,4,1,11129,2,4,2)):
        sct =  str(ext.getComponentByPosition(2))
    return sct

  def subject_common_name(self,deep=0):
    """Get subject_common_name"""
    try:
      return self._certs_nss[deep].subject_common_name
    except:
      raise Exception("subject_common_name")

  def get_cert_nss(self,deep=0):
    """Get the nss.Certificate"""
    try:
      return self._certs_nss[deep]
    except:
      raise Exception("get_cert_nss")


  def der_data(self,deep=0):
    """raw certificate DER as data buffer"""
    try:
      return self._certs_der[deep]
    except:
      raise Exception("der_data")

  def extensions(self,deep=0):
    try:
      return self._certs_nss[deep].extensions
    except:
      raise Exception("extensions")

  def _error(self):
    print '[-]Error in X509Chain'

