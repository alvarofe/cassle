#Here all related with the verification through certficate

from utils import util

class AuthCertificate():

    def __init__(self, certificate_message):
        print util.hexdump(certificate_message)

