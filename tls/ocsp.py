from  pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2560, rfc2459
from pyasn1.type import univ
import hashlib
import M2Crypto.X509
from M2Crypto.X509 import FORMAT_DER
from datetime import datetime
#from pyasn1.type.useful import GeneralizedTime

#All the code was extracted from  bit.ly/1mxntVN 

import re
import urllib2

sha1oid = univ.ObjectIdentifier((1, 3, 14, 3, 2, 26))



class ValueOnlyBitStringEncoder(encoder.encoder.BitStringEncoder):
        #These methods just do not encode tag and legnth fields of TLV
        def encodeTag(self, *args): return ''
        def encodeLength(self,*args) : return ''
        def encodeValue(*args):
            substrate, isConstructed = encoder.encoder.BitStringEncoder.encodeValue(*args)
            #encoded bit-string value
            return substrate[1:], isConstructed

        def __call__(self, bitStringValue):
            return self.encode(None, bitStringValue, defMode=1, maxChunkSize=0)


class Ocsp:
    """
    All the things related with ocsp
    """

    def __init__(self,issuer_cert, user_cert):
        self.issuer_cert = issuer_cert
        self.user_cert = user_cert
        self._extract_ocsp_uri()
        self.valueOnlyBitStringEncoder = ValueOnlyBitStringEncoder()

    def _extract_ocsp_uri(self):
        cert = M2Crypto.X509.load_cert_string(self.user_cert,FORMAT_DER)
        certificateExtensions = {}

        for index in range(cert.get_ext_count()):
            ext = cert.get_ext_at(index)
            certificateExtensions[ext.get_name()] = ext.get_value()
        try:
            infos = [x.strip() for x in certificateExtensions["authorityInfoAccess"].split('\n')]
        except KeyError:
            self.ocsp_url = None
            return
        ocsp_url = None
        for info in infos:
            if re.match(r"^OCSP - URI:", info):
                ocsp_url = info.replace("OCSP - URI:","")
                break
        self.ocsp_url = ocsp_url


    def check_ocsp(self):
        if self.ocsp_url is not None:
            try:
                issuerCert, _ = decoder.decode(self.issuer_cert,asn1Spec=rfc2459.Certificate())
                userCert, _ = decoder.decode(self.user_cert, asn1Spec=rfc2459.Certificate())
            except:
                return

            ocspReq = self.make_ocsp_request(issuerCert,userCert)

            httpReq = urllib2.Request(
                self.ocsp_url,
                encoder.encode(ocspReq),
                { 'Content-Type': 'application/ocsp-request' }
                )
            httpRsp = urllib2.urlopen(httpReq).read()

# Process OCSP response

            ocspRsp, _ = decoder.decode(httpRsp, asn1Spec=rfc2560.OCSPResponse())

            tbsResponse = self.get_ocsp_response(ocspRsp)
            self.parse_ocsp_response(tbsResponse)

        else:
            pass


    def make_ocsp_request(self,issuerCert, userCert):
        issuerTbsCertificate = issuerCert.getComponentByName('tbsCertificate')
        issuerSubject = issuerTbsCertificate.getComponentByName('subject')

        userTbsCertificate = userCert.getComponentByName('tbsCertificate')
        userIssuer = userTbsCertificate.getComponentByName('issuer')

        assert issuerSubject == userIssuer, '%s\n%s' % (
            issuerSubject.prettyPrint(), userIssuer.prettyPrint()
            )

        userIssuerHash = hashlib.sha1(
            encoder.encode(userIssuer)
            ).digest()

        issuerSubjectPublicKey = issuerTbsCertificate.getComponentByName('subjectPublicKeyInfo').getComponentByName('subjectPublicKey')

        issuerKeyHash =  hashlib.sha1(
            self.valueOnlyBitStringEncoder(issuerSubjectPublicKey)
            ).digest()


        userSerialNumber = userTbsCertificate.getComponentByName('serialNumber')

        # Build request object

        request = rfc2560.Request()

        reqCert = request.setComponentByName('reqCert').getComponentByName('reqCert')

        hashAlgorithm = reqCert.setComponentByName('hashAlgorithm').getComponentByName('hashAlgorithm')
        hashAlgorithm.setComponentByName('algorithm', sha1oid)

        reqCert.setComponentByName('issuerNameHash', userIssuerHash)
        reqCert.setComponentByName('issuerKeyHash', issuerKeyHash)
        reqCert.setComponentByName('serialNumber', userSerialNumber)

        ocspRequest = rfc2560.OCSPRequest()

        tbsRequest = ocspRequest.setComponentByName('tbsRequest').getComponentByName('tbsRequest')
        tbsRequest.setComponentByName('version', 'v1')

        requestList = tbsRequest.setComponentByName('requestList').getComponentByName('requestList')
        requestList.setComponentByPosition(0, request)

        return ocspRequest



    def parse_ocsp_response(self,tbsResponse):

        response = tbsResponse.getComponentByName('responses').getComponentByPosition(0)
        producedAt = tbsResponse.getComponentByName('producedAt')
        certId = response.getComponentByName('certID')
        certStatus = response.getComponentByName('certStatus').getName()
        nextUpdate = response.getComponentByName('nextUpdate')

        producedAt = datetime.strptime(str(producedAt), '%Y%m%d%H%M%SZ')
        nextUpdate = datetime.strptime(str(nextUpdate), '%Y%m%d%H%M%SZ')

        print('Certificate ID %s is %s at %s till %s\n' % (
            certId.getComponentByName('serialNumber'),
            certStatus,
            producedAt,
            nextUpdate))


    def get_ocsp_response(self, ocspResponse):
        responseStatus = ocspResponse.getComponentByName('responseStatus')
        assert responseStatus == rfc2560.OCSPResponseStatus('successful'), responseStatus.prettyPrint()
        responseBytes = ocspResponse.getComponentByName('responseBytes')
        #responseType = responseBytes.getComponentByName('responseType')
        #assert responseType == id_pkix_ocsp_basic, responseType.prettyPrint()

        response = responseBytes.getComponentByName('response')

        basicOCSPResponse, _ = decoder.decode(
            response, asn1Spec=rfc2560.BasicOCSPResponse()
            )

        tbsResponseData = basicOCSPResponse.getComponentByName('tbsResponseData')
        return tbsResponseData

