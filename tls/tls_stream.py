

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





from tls import tls_types
import struct
from tls.tls_verification import TLSVerificationDispatch

#The work of this class is to decode and organize all the messages that we captured
class TLSStream():
    """
    Manage a TLSStream. Basically split tls_records retrieve handshake messages
    to validate after through SSLVerificationDispatch.
    """

    def __init__(self,raw_data):
        self.cert_chain = None
        self.status_request = None
        self._process_tcp_stream(raw_data)
        self._split_tls_record()
        self._decode_tls_record()
        self._dispatch()

    def _dispatch(self):
        data = {
                "cert" : None,
                "status_request" : None
                }
        if self.cert_chain :
            data["cert"] = self.cert_chain
        if self.status_request:
            data["status_request"] = self.status_request

        TLSVerificationDispatch(data)

    def _split_tls_record(self):

        """Split the TLS stream into TLS records"""

        data = self._stream
        self._record = []
        try:
            while True:
                content_type, version_major,version_minor, length = struct.unpack_from("!BBBH",data,0)
                self._record.append(data[5:5+length])
                data = data[5+length:]
        except:
            #We reach the final of our stream
            pass


    def _process_tcp_stream(self, raw_data):
        """
        Assemblies tcp streams to process it latter.
        """

        # raw_data in reality is the stream that we collected in the function assembler in util.py
        # how we saved the data in a dictionary with the seq number we only have to order the seq number
        # and join each packet.

        aux = raw_data
        self._stream = str()
        #Sorted because we must ordered in function of the number of sequence
        for key in sorted(aux):
            self._stream += aux[key]

    def _decode_tls_record(self):

        """
        Method to extract certificate message from tls_record
        """
        #TODO tray to catch up revoked.grc.com certificate

        #You could augment this method to extract more message and add more logic to the application
        #Sometimes after a server hello comes a certificate

        for record in self._record:

            try:
                #content_type = struct.unpack_from("!B",record,0)[0]
                message_type,message_length = struct.unpack_from("!BI",record,0)
                message_length >>= 8
                if message_type == tls_types.TLS_H_TYPE_SERVER_HELLO:
                    data = record[4+message_length:]
                    _type,_length = struct.unpack_from("!BI",data,0)
                    _length >>=8
                    if _type == tls_types.TLS_H_TYPE_CERTIFICATE:
                        self._decode_certificate(data[4:4+_length])
                if message_type == tls_types.TLS_H_TYPE_CERTIFICATE:
                    self._decode_certificate(record[4:4+message_length])
            except:
                #We treat with the at least a record incompleted o corrupted
                pass


    def _decode_certificate(self,cert_handshake):
        data = cert_handshake
        self.cert_chain = []
        cert_length = struct.unpack_from("!I",data,0)[0]>>8
        data = data[3:]
        total_length = 0
        while total_length != cert_length:
            length = struct.unpack_from("!I",data,0)[0]>>8
            total_length += length + 3
            self.cert_chain.append(data[3:3+length])
            data = data[3+length:]



