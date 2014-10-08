

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

from tls.auth_certificate import AuthCertificate
import Queue
import threading

screen_lock = threading.Lock()


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

            # The queue will be use to return the result of the validation. With that note we will provide a answer if our connection is secure enough to continue navigating
            result_queue = Queue.Queue()
            # The screen_lock will be shared for all the instance that is running 
            auth_cert_thread = AuthCertificate(self.certificates,result_queue, screen_lock)
            auth_cert_thread.daemon = True
            auth_cert_thread.start()
            #print result_queue.get()

        else:
            pass

    # Our project won't add OCSP stapling support because is not widely support. But like we did for certificate message 
    # the same way would be for the OCSP stapling message in the handshake. Once we have it add all the logic necessary to validate it
    def verify_auth_ocsp_stapling(self):
        if self.ocsp_stapling is not None:
            #verify connection through ocsp_stapling
            #In the future only add here all the code needed
            pass
        else:
            pass
