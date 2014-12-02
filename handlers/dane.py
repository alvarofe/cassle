from handlers import handlers, handler
from handlers.base import BaseHandler
import dns.resolver
from conf import config, debug_logger
import logging
import hashlib


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
    cert = True
    ocsp = False

    def on_certificate(self, cert):
        def verify(url):
            try:
                answer = dns.resolver.query('_443._tcp.' + url, 'TLSA')
            except:
                # print "Unexpected error:", sys.exc_info()[0]
                return False

            (
                cert_usage,
                selector,
                match_type,
                associated_data
            ) = [str(ans) for ans in answer][0].split(' ')
            funct = [cert.der_data, cert.subject_public_key_info]
            hash_funct = [None, hashlib.new('sha256'), hashlib.new('sha512')]
            temp = hash_funct[int(match_type)]

            # depend on the match_type we need use different algorithms

            if cert_usage == '3' or cert_usage == '1':
                # depend on the selector file we use the whole certificate or
                # only the subjectPublicKeyInfo
                data = funct[int(selector)]()
                if temp is not None:
                    temp.update(data)
                    data = temp.hexdigest()
                if data == associated_data:
                    return True
                else:
                    return False

            if cert_usage == '0':
                # We must check for each certificate in the chain that the
                # associated data is presented

                # if you visit https://fedoraproject.org the TLSA record is as
                # follow: 0 0 1 (associated data) but the chain is only 2 maybe
                # the associated data is related with the root CA so we are not
                # able to match that because of we do not have the whole chain.

                for cer in xrange(0, cert.length_chain()):
                    data = funct[int(selector)](deep=cer)
                    if temp is not None:
                        temp.update(data)
                        data = temp.hexdigest()
                    print data, associated_data

                    if data == associated_data:
                        return True
                    return False

            if cert_usage == '2':
                debug_logger.debug("\t[-] We do not support this yet")
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
        debug_logger.debug(
            "\t[-] Certificate {0} has not a valid TLSA".format(
                cert.ca_name()) + " record or it doesn't implement DANE")


