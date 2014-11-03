

# Copyright (C) 2014       Alvaro Felipe Melchor (alvaro.felipe91@gmail.com)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


#Here all related with the verification through certficate


import threading
import nss.nss as nss
from termcolor import colored
from db.database import Database
from tls.ocsp import Ocsp
from nss.error import NSPRError
from utils.event_notification import MITMNotification
from utils.notification_osx import NotificationOSX
from utils.log import log_info
from config import config

intended_usage = nss.certificateUsageSSLServer

#TODO # add configuration and log and sendemail when a mitm happened

class AuthCertificate(threading.Thread):
    """
    This class validate the authentication of each certificate we see with different techniques
    """

    def __init__(self, cert ,queue, screen_lock):
        """
        Constructor of AuthCertificate

        Parameters:
            -certificates: The certificate chain. It represents by cert.py
            -queue: Here we will return the result of our verification
            -screen_lock: Lock used to print in the screen
        """

        threading.Thread.__init__(self)
        self.lock = screen_lock
        self.queue = queue
        self.cert = cert
        MITMNotification.register(NotificationOSX())

        try:
            self.ocsp =  Ocsp(cert)
        except:
            pass

        db_name = config.DB_NAME
        self.db_pin = Database(db_name, "pinning")
        self.db_log = Database(db_name, "log")
        self.db_blacklist = Database(db_name, "blacklist")


    def run(self):
        if self.cert.deep() == 1:
            #Could be this an attack??
            #I think that is more at bad deployment
            cad =  'We need all the chain to validate --> ' + self.cert.ca_name()
            self._print_screen(message=cad)
            return

        #based on our configuration file we apply different methods to use

        if config.V_RFC == True:
            self.verify_cert_through_rfc()

        if config.V_DNSSEC == True:
            self.verify_dnssec_tlsa()

        if config.V_PINNING == True:
            self.verify_cert_with_pinning()

        if config.V_ICSI == True:
            self.verify_cert_with_icsi_notary()

        if config.V_OCSP == True:
            self.verify_ocsp()

        if config.V_CT == True:
            self.verify_ct()

        if config.V_BLACKLIST == True:
            self.verify_ssl_blacklist()


    def verify_ssl_blacklist(self):
        """
        We take our der-certificate and compare the fingerprint against the sslblacklist to ensure
        that we are not connected to malware site
        """
        name = self.cert.ca_name()
        fingerprint = self.cert.hash()
        query = self.db_blacklist.get(fingerprint)
        if query == None:
            cad = 'The certificate %s is  safe against SSL-BLACKLIST database' % (name)
            self._print_screen(message=cad,color='white')
        else:
            cad = 'You connected a site that uses a Certificate (%s) that match with malware-certificate' % (name)
            self._print_screen(message=cad,color='white')


    def verify_ct(self):
        """
        Certificate Transparency Log

        If we read in the RFC.

        <whe should validate the SCT by computing the signature input from the SCT data as well as the
        certificate and verifying the signature, using the corresponding log's public key.
        NOTE that this document does not describe how clients obtain the log' public keys.
        TLS clients MUST reject SCTs whose timestamp is in the future.>

        For now the only thing that we can do is to ensure that the timestamp ain't in the future.
        Because there isn't way to know the certificate's server log to extract the public key
        """
        #TODO parse SignedCertificateTimestamp

        #self.ocsp.check_certificate_transparency()
        sct = self.cert.get_ct_extension()
        if sct != None:
            with self.lock:
                print self.cert.ca_name()
                print 'Signed Certificate Timestamp found ' + sct.encode('hex')
        else:
            s = self.ocsp.check_certificate_transparency()
            if s != None:
                with self.lock:
                    print s


    def verify_dnssec_tlsa(self):
        """
        DNNSEC/TLSA

        We retrieve the TLSA record of the domain and compare both fingerprints. If they are equal everything OK
        If not it could be a possible attack. Now perhaps isn't realistic because isn't widely deployed and some sites
        does not update the TLSA record for its domain. This need maybe more research
        """
        import dns.resolver

        def verify(url):
            try:
                #print '_443._tcp. + url
                #TODO read better the RFC
                #TODO check for a extension to extract all the url the subject alternative name
                answer = dns.resolver.query('_443._tcp.' + url, 'TLSA')
                answer = [str(ans) for ans in answer][0].split(' ')
                hash_tlsa = answer[len(answer) - 1]
                res = self.cert.hash(algorithm='sha256')
                if res == hash_tlsa:
                    return True
                else:
                    return False
            except:
                return False
                # pass

        try:
            url = self.cert.subject_common_name()
        except IndexError:
            return


        # Here I test different url because some site maybe implements dnssec without the wwww for example.
        # the site https://hacklab.to/ when you see its certificate the subject_common_name is www.hacklab.to
        # but the dnssec only respond when you ask for hacklab.to. So I have to test with different url to ensure
        # all the posibilities and provide better solution.

        # Site where you can test this verification
        #   - https://www.huque.com/  -> Valid TLSA Record
        #   - https://hacklab.to/  -> Not Valid TLSA Record

        result = False
        result = verify(url)

        if result == True:
            cad = 'The certificate %s with id %s has a valid TLSA record' % (self.cert.ca_name(), self.cert.serial_number())
            self._print_screen(message=cad,color='magenta')
            return
        if url[0:3] == "www":
            url = url.replace("www.",'')
            result = verify(url)
        elif url[0] == '*':
            url = url.replace('*', 'www')
            result = verify(url)
        if result == True:
            cad =  'The certificate %s with id %s has a valid TLSA record' % (self.cert.ca_name() ,self.cert.serial_number())
            self._print_screen(message=cad,color='magenta')
            return
        cad =  'The certificate %s with id %s has not a valid TLSA record or not implement DANE/DNSSEC' % (self.cert.ca_name(), self.cert.serial_number())
        self._print_screen(message=cad,color="white")

    def verify_ocsp(self):
        """
        We check the OCSP status of our certificate

        Visit this domain : https://testssl-revoked-r2i2.disig.sk/index.en.html

        This software if it is running in Mac OS X will show you a notification seeing that the site is revoked.
        """

        #TODO check that we are not under a reply attack
        status, certId = self.ocsp.check_ocsp()
        name = self.cert.ca_name()
        if status == None:
            #Should be this consider as an error?
            cad = 'The certificate %s with id  %s does not have OCSP URI' % (name, certId)
            self._print_screen(message=cad,color='white')
            return
        if status == 'revoked':
            MITMNotification.notify(title="OCSP", message=self.cert.subject_common_name())
            cad =  'This certificate %s with id  %s is revoked' % (name, certId)
            self._print_screen(message=cad)
            self._log_fail()
        else:
            cad = 'This certificate %s with id %s is not revoked' % (name, certId)
            self._print_screen(message=cad,color='cyan')

    def verify_cert_through_rfc(self):
            """
            This function try verify the certificate through RFC especification. We are using NSS to do it
            """
            approved_usage = not intended_usage
            try:
                # Turns on OCSP checking for the given certificate database.
                cert = self.cert.get_cert_nss()
                ca_name = self.cert.ca_name()
                certdb = self.cert.get_nssdb()
                # Verify a certificate by checking if it's valid and if we trust the issuer. Here we are validating our certificate for SSLServer
                approved_usage = cert.verify_now(certdb,True,intended_usage,None)

            except NSPRError:
                #Error ocurred is maybe due to a missed intermediate certificate so we should added but without confidence on it
                log_info(message="NSPError in verify_cert_through_rfc ")
                length = self.cert.deep()
                self.cert.add_to_nssdb(cert.issuer.common_name,1)
                #self._add_certiticate_to_nssdb(1,name=cert.issuer.common_name)
                if length == 4:
                    inter = self.cert_nss[1]
                    self.cert.add_to_nssdb(inter.issuer.common_name, 2)
                    #self._add_certiticate_to_nssdb(2,name=inter.issuer.common_name)
                if length > 4:
                    MITMNotification.notify(title="Chain large",message="We don't support at chain mayor than 4")
                try:
                    approved_usage = cert.verify_now(certdb,True, intended_usage, None)
                except NSPRError:
                    log_info(message="NSPError in verify_cert_through_rfc ")

            serial = str(cert.serial_number)

            if approved_usage & intended_usage:
                cad = 'This certificate %s is safe through the RFC process ' % (serial + ' - ' + ca_name)
                self._print_screen(message=cad,color='green')
            else:
                cad = 'This certificate %s is not safe through the RFC process ' % (serial + ' - ' + ca_name)
                self._print_screen(message=cad)
                self._log_fail()
                MITMNotification.notify(title="RFC", message=self.cert.subject_common_name())


    def verify_cert_with_pinning(self):
        """
        We pin our certificates each time that we see it.
        """
        try:
            # We extract SubjectPublicKeyInfo


            hash_t = self.cert.hash_spki()
            #cert = self.cert_nss[0]
            serial = self.cert.serial_number()
            _id = str(serial) + ' - ' + self.cert.ca_name()
            exist = self.db_pin.get(_id)
            if exist == None:
                # That means that the certificate is not in the database, it's the first time it was seen
                self.db_pin.set_pin(hash_t, _id)
                cad = "%s first seen" % _id
                self._print_screen(message=cad,color='yellow')
            else:
                # Exist so we have to ensure it's correct
                correct = self.db_pin.compare(_id, hash_t)
                if correct == False:
                    cad = 'This certificate %s changed' % _id
                    self._print_screen(message=cad)
                    MITMNotification.notify(title='Pinning', message = self.cert.subject_common_name())
                    self._log_fail()

                else:
                    cad = 'Nothing changed ' + _id
                    self._print_screen(message=cad,color='yellow')
        except Exception:
            log_info(message="Exception in verify_cert_with_pinning")


    def verify_cert_with_icsi_notary(self):

        """
        ICSI_NOTARY is used to know the "fame" of a certificate. It Provides a fashion to know if a certificate
        is widely seen. But it doesn't mean we are under MITM attack. You should configure in the config file
        when you want received a notification from ICSI. How many days for you is enough to consider it a MITM.
        """

        import dns
        from dns import resolver
        address = self.cert.hash()+'.notary.icsi.berkeley.edu'
        try:
            result =  resolver.query(address,rdtype=dns.rdatatype.TXT)[0].__str__().split()
        except:
            #icsi_notary doesn't have that certificate
            cad = "icsi notary does not have that cert"
            self._print_screen(message=cad,color='white')
            return

        validated = int(result[4].split('=')[1][0])
        first_seen = int(result[1].split('=')[1])
        last_seen = int(result[2].split('=')[1])
        times_seen = int(result[3].split('=')[1])
        if validated is not 1:
            cad = "This certificate %s is NOT safe through icsi_notary" % (self.cert.ca_name())
            self._print_screen(message=cad)
        else:
            s = last_seen - first_seen  + 1
            if s - times_seen >= config.ICSI_MAXIMUM_INTERVAL:
                cad = "This certificate %s is not ENOUGH secure according to icsi_notary" % (self.cert.ca_name())
                MITMNotification.notify(title='ICSI', message = self.cert.subject_common_name())
                self._print_screen(message=cad,color='red')

            else:
                cad = "This certificate %s IS SECURE through icsi_notary" % (self.cert.ca_name())
                self._print_screen(message=cad,color='blue')


    def _log_fail(self):
        #Here we only log each certificate that produces an mitm but only once. This approach if for don't full the
        #log file. You are free to log whatever you want
        cn_cert = self.cert.get_cert_nss()
        name = cn_cert.make_ca_nickname()
        exist = self.db_log.get(name)
        if exist is None:
            self.db_log.set_rfc(cn_cert.make_ca_nickname())
            message = "You don't trust in this certificate when you connected to %s \n %s" %  (name, cn_cert)
            log_info(message=message)



    def _print_screen(self,message="MITM", color= "red"):
        """Simple method to print in the screen when an error happen"""
        with self.lock:
            print colored(message,color)


