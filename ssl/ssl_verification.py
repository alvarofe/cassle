
from ssl.auth_certificate import AuthCertificate

class SSLVerificationDispatch():

    def __init__(self, data):
        
        self.certificate = None
        self.ocsp_stapling = None

        if 'certificate' in data:
            self.certificate = data['certificate']
        if 'ocsp_stapling' in data:
            self.ocsp_stapling = data['ocsp_stapling']
        self.verify_auth_certificate()
        self.verify_auth_ocsp_stapling()


    def verify_auth_certificate(self):
        #Do everything related with certificate
        if self.certificate is not None:
            #verify certificate
            AuthCertificate(self.certificate.decode('hex'))
        else:
            pass

    def verify_auth_ocsp_stapling(self):
        if self.ocsp_stapling is not None:
            #verify connection through ocsp_stapling
            #In the future only add here all the code needed
            pass
        else:
            pass
