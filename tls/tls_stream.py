

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

#This gonna be a class that we'll be initialized with raw data. self.messages will contain all the tls message related with handshake

from tls import tls_types
#import sys
from utils.util import hexdump
from tls.tls_verification import TLSVerificationDispatch

#TODO try find another name for this class
#The work of this class is to decode and organize all the messages that we captured
class TLSStream():
    """
    Manage a TLSStream. Basically split tls_records retrieve handshake messages
    to validate after through SSLVerificationDispatch.
    """

    def __init__(self,raw_data):
        self._process_tcp_stream(raw_data)
        self._decode_tls_record()
        self._decode_certificate()
        if self._found :
            data = {
                    'certificate' : self.cert
                    }
            TLSVerificationDispatch(data)

    def _process_tcp_stream(self, raw_data):
        """
        Method that assemblies tcp streams to process it latter. 
        """

        # raw_data in reality is the stream that we collected in the function assembler in util.py
        # how we saved the data in a dictionary with the seq number we only have to order the seq number
        # and split each packet.
        aux = raw_data
        self._handshake_message = str()
        #Sorted because we must ordered in function of the number of sequence
        for key in sorted(aux):
            self._handshake_message += aux[key]

    def _decode_tls_record(self):
        """
        Method to extract certificate message from tls_record
        """

        #TODO try to refactor here

        # To understand better this use wireshark to disseminate each message and see
        # each structure
        
        message = self._handshake_message.encode('hex')
        self._found = False
        try:
            if message[0:2] == tls_types.TLS_HANDSHAKE:
                if message[10:12] == tls_types.TLS_H_TYPE_SERVER_HELLO:
                    length = int(message[12:18],16)
                    next = 18 + (length * 2)
                    if message[next : next + 2] == tls_types.TLS_HANDSHAKE:
                        next += 10
                        if message[next:next + 2] == tls_types.TLS_H_TYPE_CERTIFICATE:
                            self._found = True
                            self.cert_message = message[next + 2:]
                    elif message[next:next + 2] == tls_types.TLS_H_TYPE_CERTIFICATE:
                        self._found = True
                        self.cert_message = message[next + 2:]
                elif message[10:12] == tls_types.TLS_H_TYPE_CERTIFICATE:
                    self._found = True
                    self.cert_message = message[12:]

            elif message[0:2] == tls_types.TLS_ALERT:
                length = int(message[6:10],16)
                next = 10 + (length * 2)
                if message[next:next + 2] == tls_types.TLS_HANDSHAKE:
                    message = message[next:]
                    if message[10:12] == tls_types.TLS_H_TYPE_SERVER_HELLO:
                        length = int(message[12:18],16)
                        next = 18 + (length * 2)
                        if message[next : next + 2] == tls_types.TLS_HANDSHAKE:
                            next += 10
                            if message[next:next + 2] == tls_types.TLS_H_TYPE_CERTIFICATE:
                                self._found = True
                                self.cert_message = message[next + 2:]
                        elif message[next:next + 2] == tls_types.TLS_H_TYPE_CERTIFICATE:
                            self._found = True
                            self.cert_message = message[next + 2:]
                    elif message[10:12] == tls_types.TLS_H_TYPE_CERTIFICATE:
                        self._found = True
                        self.cert_message = message[12:]
        except:
            print 'error in _decode_tls_record in tls_stream'
            # pass


    def _decode_certificate(self):
        if self._found == True:
            self.cert = list()
            try:
                chain_length = int(self.cert_message[6:12] , 16)
            except ValueError:
                return
            total_length = 0
            aux = self.cert_message[12:]
            while True:
                try:
                    if (aux[0:2] == tls_types.TLS_HANDSHAKE and aux[10:12] == tls_types.TLS_H_TYPE_SERVER_HELLO_DONE)\
                            or aux[0:2] == tls_types.TLS_H_TYPE_SERVER_HELLO_DONE:
                        break
                    length = int(aux[0:6],16)
                    total_length += (length + 3)
                    next = 6 + (length * 2)
                    self.cert.append(aux[6:next].decode('hex'))
                    if total_length == chain_length:
                        break
                    aux = aux[next:]
                except ValueError:
                    return
        else:
            return



