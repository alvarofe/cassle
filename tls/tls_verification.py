

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

import threading
from tls.cert import X509Chain
from handlers import handlers
from tls.ocsp import Ocsp

screen_lock = threading.Lock()


class TLSVerificationDispatch():

    def __init__(self, data):

        self.certs = None
        self.status_request = None
        if 'cert' in data:
            self.certs = data['cert']
        if 'status_request' in data:
            self.status_request = data['status_request']
        self.dispatch_certificate()
        self.dispatch_status_request()


    def dispatch_certificate(self):
        #screen_lock is only to print in the console
        global screen_lock
        #Do everything related with certificate
        if self.certs is not None:
            #verify certificate
            try:
                chain = X509Chain(self.certs)
            except Exception as e:
                print e
                return
            if chain.length_chain() == 1:
                print '[-] Chain incomplete'
                return
            else:
                ocsp = Ocsp(chain)
                print '[+] Verifying certificate'
                for cls in handlers.store:
                    instance = handlers.store[cls]()
                    if instance.cert == True:
                        instance.on_certificate(chain)
                    if instance.ocsp == True:
                        instance.on_ocsp_response(ocsp)

        else:
            pass


    def dispatch_status_request(self):
        if self.dispatch_status_request is not None:
            #verify connection through ocsp_stapling
            #In the future only add here all the code needed
            pass
        else:
            pass



