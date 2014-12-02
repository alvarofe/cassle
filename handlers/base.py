class BaseHandler():

    """
    Basic Class to extend its functionality to validate either certificate or
    ocsp_response
    """

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

