


class BaseHandler():

    def on_certificate(self,cert):
        """
        You must implement this method to received the certificate and work with it
        """
        return

    def on_ocsp_response(self,ocsp):
        """
        You must implement this method to received the ocsp response
        """
        return
