class BaseHandler(object):

    """
    Basic Class to extend its functionality to validate either certificate,
    ocsp_response or both
    """

    def __init__(self, cert, ocsp):
        super(BaseHandler, self).__init__()
        self._cert = cert
        self._ocsp = ocsp

    def on_certificate(self, cert):
        """
        You must implement this method to received the certificate and work
        with it
        """
        return

    def on_ocsp_response(self, ocsp):
        """
        You must implement this method to received the ocsp response
        """
        return


