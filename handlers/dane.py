
from handlers import handlers, handler
from handlers.base import BaseHandler
import dns.resolver
from conf import config, debug_logger
import logging
import hashlib
import nss.nss as nss
from tls import nssconfig
from nss.error import NSPRError


intended_usage = nss.certificateUsageSSLServer

logger = logging.getLogger(__name__)


# Introduce DANE is kinda complicated because of we do not have any means to
# know where the user is trying to connect because we need the name domain to
# make a dns query. To address this problem we extract the subject_common_name
# from the certificate and try different schemes. But is not enough. One
# example is you try to visit https://good.dane.verisignlabs.com/ it has a
# valid TLSA record but the cert's subjectCommonName is *.dane.verisign.lab.
# In this case to retrieve the TLSA record we should use
# good.dane.verisignlabs.com but we have dane.verisign.lab so we are not able
# to check this TLSA.

# Another problem that we have is if we do not have the whole chain.
# If the TLSA record received is something like 0 0 1 (associated data)
# maybe the data associated makes a reference to the CA root. It is
# important that the whole chain is presented.

# Also remember that we are not using DNSSEC along with DANE
# so could be possible being under a possible attack due to
# someone would impersonate the dns server


@handler(handlers, isHandler=config.V_DANE)
class Dane(BaseHandler):

    name = "dane"

    def __init__(self, cert, ocsp):
        super(Dane, self).__init__(cert, ocsp)
        self.on_certificate(cert)

    def verify_chain(self, cert):
        approved_usage = not intended_usage
        try:
            length = cert.length_chain()
            if length > 4:
                return False
            cert_nss = cert.get_cert_nss()
            certdb = nssconfig.certdb
            approved_usage = cert_nss.verify_now(
                certdb, True, intended_usage, None)
        except NSPRError:
            cert.add_to_nssdb(cert_nss.issuer.common_name, deep=1)
            if length == 4:
                inter = cert.get_cert_nss(deep=1)
                cert.add_to_nssdb(inter.issuer.common_name, deep=2)
            try:
                approved_usage = cert_nss.verify_now(
                    certdb, True, intended_usage, None)
            except NSPRError:
                pass

        if approved_usage & intended_usage:
            return True
        else:
            return False

    def on_certificate(self, cert):

        def verify(url):
            try:
                answer = dns.resolver.query('_443._tcp.' + url, 'TLSA')
            except:
                # print "Unexpected error:", sys.exc_info()[0]
                return -1

            (
                cert_usage,
                selector,
                match_type,
                associated_data
            ) = [str(ans) for ans in answer][0].split(' ')
            funct = [cert.der_data, cert.subject_public_key_info]
            hash_funct = [None, hashlib.sha256, hashlib.sha512]
            temp = hash_funct[int(match_type)]

            # depend on the match_type we need use different algorithms

            if cert_usage == '3' or cert_usage == '1':
                # depend on the selector file we use the whole certificate or
                # only the subjectPublicKeyInfo
                data = funct[int(selector)]()
                if temp is not None:
                    m = temp(data)
                    data = m.hexdigest()
                if data == associated_data:
                    return True
                else:
                    return False

            if cert_usage == '0' or cert_usage == '2':
                # We must check for each certificate in the chain that the
                # associated data is presented

                # if you visit https://fedoraproject.org the TLSA record is as
                # follow: 0 0 1 (associated data) but the chain is only 2 maybe
                # the associated data is related with the root CA so we are not
                # able to match that because of we do not have the whole chain.

                for cer in xrange(0, cert.length_chain()):
                    data = funct[int(selector)](deep=cer)
                    if temp is not None:
                        m = temp(data)
                        data = m.hexdigest()

                    if data == associated_data:
                        if cert_usage == '0':
                            return True
                        else:
                            cert.add_to_nssdb(
                                cert.subject_common_name(deep=cer),
                                deep=cer)
                            value = self.verify_chain(cert)
                            cert.remove_from_nssdb(
                                cert.subject_common_name(deep=cer)
                                )
                            return value
                return False

        try:
            url = cert.subject_common_name()
        except IndexError:
            debug_logger.debug("\t[-] ERROR extracting subject_common_name")
            return

        result = False
        result = verify(url)

        if result is True:
            debug_logger.debug(
                "\t[+] Certificate %s has a valid TLSA record" %
                cert.ca_name()
                )
            return

        if url[0:3] == "www":
            url = url.replace("www.", '')
            result = verify(url)

        if url[0] == '*':
            url = url.replace('*', 'www')
            result = verify(url)
            if result is True:
                debug_logger.debug(
                    "\t[+] Certificate %s has a valid TLSA record" %
                    cert.ca_name()
                    )
                return

            url = url.replace('www', '*')

        if url[0] == '*.':
            url = url.replace('*.', '')
            result = verify(url)

        if result is True:
            debug_logger.debug(
                "\t[+] Certificate %s has a valid TLSA record" %
                cert.ca_name()
                )
            return
        if result == -1:
            debug_logger.debug(
                "\t[-] Certificate {0} does not implement DANE".format(
                    cert.ca_name()))
            return

        debug_logger.debug(
            "\t[-] Certificate {0} has not a valid TLSA".format(
                cert.ca_name()))


