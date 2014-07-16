###############################################################################################
### Name: ssl_verification.py
### Author: Alvaro Felipe Melchor - alvaro.felipe91@gmail.com
### Twitter : @alvaro_fe
### University of Alcala de Henares
###############################################################################################

from tls.auth_certificate import AuthCertificate
import Queue
import threading

screen_lock =threading.Semaphore(value=1)


class TLSVerificationDispatch():

    def __init__(self, data):

        self.certificates = None
        self.ocsp_stapling = None

        if 'certificate' in data:
            self.certificates = data['certificate']
        if 'ocsp_stapling' in data:
            self.ocsp_stapling = data['ocsp_stapling']
        self.verify_auth_certificate()
        self.verify_auth_ocsp_stapling()


    def verify_auth_certificate(self):
        #Do everything related with certificate
        if self.certificates is not None:
            #verify certificate
            result_queue = Queue.Queue()
            auth_cert_thread = AuthCertificate(self.certificates,result_queue, screen_lock)
            auth_cert_thread.daemon = True
            auth_cert_thread.start()
            #print result_queue.get()

        else:
            pass

    #TODO add everything to parse and use ocsp_stapling firefox support ocsp_stapling
    def verify_auth_ocsp_stapling(self):
        if self.ocsp_stapling is not None:
            #verify connection through ocsp_stapling
            #In the future only add here all the code needed
            pass
        else:
            pass
