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
import threading
import nss.nss as nss
import os
import platform
from pync import Notifier
from termcolor import colored
from db.database import database
from tls.ocsp import Ocsp
import subprocess, tempfile
from nss.error import NSPRError

#TODO add rfc support, improved ocsp with CT 



from config import Config

#Configuration stuff
f = file('config/config.cfg')
cfg = Config(f)
f.close()
#


intended_usage = nss.certificateUsageSSLServer

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

#TODO save in a list each nss.Certificate because we use it a lot of

class AuthCertificate(threading.Thread):
    """
    This class validate the authentication through certificate
    """

    def __init__(self, certificates,queue, screen_lock):

        #The queue is used to return data to the main thread
        threading.Thread.__init__(self)
        self.lock = screen_lock
        self.queue= queue
        self.certs = certificates

        self.cert_nss = list()

        certdb = os.path.expanduser(cfg.config.NSS_DB_DIR)

        nss.nss_init(certdb)
        self.certdb = nss.get_default_certdb()

        for i in xrange(0,len(self.certs)):
            try:
                self.cert_nss.append(nss.Certificate(self.certs[i],self.certdb))
            except:
                break


        db_name = cfg.db.db_name
        self.db_pin = database(db_name, cfg.db.coll_name_pinning)
        self.db_rfc = database(db_name, cfg.db.coll_name_log)

        #self._print_first_certificate_of_chain()

    def run(self):
        #TODO add here execution based on the configuration file
        self.verify_cert_through_rfc()
        self.verify_dnssec_tlsa()
        self.verify_cert_with_pinning()
        self.verify_cert_with_icsy_notary()
        self.lock.acquire()
        self.verify_ocsp()
        self.lock.release()

    """
    Methods that implement verification using the certificate
    """

    def verify_dnssec_tlsa(self):
        import dns.resolver
        import hashlib
        try:
            url = self.cert_nss[0].subject_common_name
        except IndexError:
            return
        if url[0] == '*':
            url = url.replace('*', 'www')
        try:
            #print '_443._tcp.' + url
            answer = dns.resolver.query('_443._tcp.' + url, 'TLSA')
            answer = [str(ans) for ans in answer][0].split(' ')
            hash_tlsa = answer[len(answer) - 1]
            s = hashlib.new('sha256')
            s.update(self.certs[0])
            res = s.hexdigest()
            if res == hash_tlsa:
                print 'DANE secure'
        except:
            #print 'No TLSA'
            pass

    def _compare_usage(self,intended,approved):
            if approved & intended:
                return True
            else:
                return False

    def _log_fail(self,num_cert,ca_name):
            cn_cert = self.cert_nss[num_cert]
            exist = self.db_rfc.get(cn_cert.make_ca_nickname())
            if exist is None:
                self.db_rfc.set_rfc(cn_cert.make_ca_nickname())
                # print cn_cert
                logging.info("You don't trust in this certificate when you connected to %s \n %s",
                                ca_name, cn_cert)

    def verify_ocsp(self):
        try:
            ocsp = Ocsp(self.certs[1],self.certs[0])
        except IndexError:
            return
        ocsp.check_ocsp()

    #TODO refactor this
    def verify_cert_through_rfc(self):
            """
            This function try verify the certificate through RFC espefication. We are using NSS to do it
            """
            if len(self.cert_nss) == 0:
                return
            cert_is_valid = False
            approved_usage = not intended_usage
            try:
                # Turns on OCSP checking for the given certificate database. But only in the database not in the actual certificate of our site
                nss.enable_ocsp_checking(self.certdb)
                # Convert der data to nss.Certificate class to manipulate things latter
                cert = self.cert_nss[0]
                ca_name = cert.make_ca_nickname()
                # Verify a certificate by checking if it's valid and that we trust the issuer. Here we are validating our certificate for SSLServer 
                approved_usage = cert.verify_now(self.certdb,True,intended_usage,None)

            except NSPRError:

                #Refactor all this chain of try and except. The pattern is always the same so is possible to refactor it, find the way to do it    

                # The exception could happen due to miss of the intermediate certificate in NSS-DB
                length = len(self.certs)
                if length == 2:
                    self._add_certiticate_to_nssdb(1,name=cert.issuer.common_name)
                    try:
                        approved_usage = cert.verify_now(self.certdb,True,intended_usage,None)
                        #print colored('This certificate %s is safe through the RFC process ' % cert.make_ca_nickname(),'green')
                    except NSPRError:
                        cert_is_valid = self._compare_usage(intended_usage, approved_usage)
                        if cert_is_valid == False:
                            self._log_fail(0, ca_name)
                            self._notify_mitm(title=ca_name)
                            self.lock.acquire()
                            print colored('This certificate %s is not safe through the RFC process ' % ca_name,'red')
                            self.lock.release()


                elif length == 3:
                    # Something wrong happened maybe was because the intermediate certificate ain't in the NSS-DB            
                    self._add_certiticate_to_nssdb(1,name=cert.issuer.common_name)
                    try:
                        approved_usage = cert.verify_now(self.certdb,True,intended_usage,None)
                        #print colored('This certificate %s is safe through the RFC process ' % ca_name,'green')
                    except NSPRError:
                        cert_is_valid = self._compare_usage(intended_usage, approved_usage)
                        if cert_is_valid == False:
                            self._log_fail(2, ca_name)
                            self._notify_mitm(title=ca_name)
                            self.lock.acquire()
                            print colored('This certificate %s is not safe through the RFC process ' % ca_name,'red')
                            self.lock.release()
                            # print nss.cert_usage_flags(approved_usage)
                            # print e.strerror

                elif length == 4:
                    self._add_certiticate_to_nssdb(1,name=cert.issuer.common_name)
                    inter = self.cert_nss[1]
                    self._add_certificate_to_nssdb(2,name=inter.issuer.common_name)
                    try:
                        approved_usage = cert.verify_now(self.certdb,True,intended_usage,None)
                        # print colored('This certificate %s is safe through the RFC process ' % ca_name,'green')
                    except NSPRError:
                        cert_is_valid = self._compare_usage(intended_usage, approved_usage)
                        if cert_is_valid == False:
                            self._log_fail(3, ca_name)
                            self._notify_mitm(title=ca_name)
                            self.lock.acquire()
                            print colored('This certificate %s is not safe through the RFC process ' % ca_name,'red')
                            self.lock.release()


            cert_is_valid = self._compare_usage(intended_usage, approved_usage)
            if cert_is_valid == True:
                self.lock.acquire()
                print colored('This certificate %s is safe through the RFC process ' % ca_name,'green')
                self.lock.release()


    def verify_cert_with_pinning(self):
        import hashlib
        from Crypto.Util.asn1 import DerSequence
        import sha3
        s = hashlib.new("sha3_512")
        #aux = nss.Certificate(self.certs[0],self.certdb)
        if len(self.cert_nss) == 0:
            return
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
            cert = self.cert_nss[0]
            serial = cert.serial_number
            _id = str(serial) + ' - ' + cert.make_ca_nickname()
            exist = self.db_pin.get(_id)
            if exist == None:
                # That means that the certificate is not in the database, it's the first time it was seen
                self.db_pin.set_pin(hash_t, _id)
                cad = "%s first seen" % _id
                self.lock.acquire()
                print colored(cad,'yellow')
                self.lock.release()
            else:
                # Exist so we have to ensure it's correct
                correct = self.db_pin.compare(_id, hash_t)
                if correct == False:
                    cad = 'This certificate %s changed' % _id
                    self.lock.acquire()
                    print colored(cad,'red')
                    self.lock.release()
                    self._notify_mitm(title=_id)

                else:
                    cad = 'Nothing changed ' + _id
                    self.lock.acquire()
                    print colored(cad,'yellow')
                    self.lock.release()
        except Exception:
            pass


    def verify_cert_with_icsy_notary(self):
        import hashlib
        import dns
        from dns import resolver
        if len(self.cert_nss) == 0:
            return
        cert = self.cert_nss[0]
        s = hashlib.new("sha1")
        s.update(self.certs[0])
        address = s.hexdigest()+'.notary.icsi.berkeley.edu'
        try:
            result =  resolver.query(address,rdtype=dns.rdatatype.TXT)[0].__str__().split()
        except:
            print s.hexdigest()
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

    def _add_certiticate_to_nssdb(self,cert,name=None,trust=False):

        """
        This function add intermediate certificate to NSS-DB only to verify. We don't trust on it
        If you want to trust in it, only set trust param to True
        """

        if not os.path.exists(os.getcwd() +'/tmp'):
            os.mkdir(os.getcwd() + '/tmp')

        with tempfile.NamedTemporaryFile(dir=os.getcwd() +'/tmp',suffix='crt') as tmp:
            try:
                tmp.write(M2Crypto.X509.load_cert_string(self.certs[cert],FORMAT_DER).as_pem())
            except:
                print self.cert_nss[cert] 
            tmp.flush
            tmp.seek(0)
            if not trust:
                subprocess.call(["certutil", "-A","-n",name,'-t',',,,','-a','-i',tmp.name,'-d',self.certdb_dir])
            else:
                subprocess.call(["certutil", "-A","-n",name,'-t','C,,,','-a','-i',tmp.name,'-d',self.certdb_dir])
        return



