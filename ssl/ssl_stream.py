#This gonna be a class that we'll be initialized with raw data. self.messages will contain all the tls message related with handshake

from ssl import ssl_types
#import sys
#from utils import util
from ssl.ssl_verification import SSLVerificationDispatch

#TODO try find another name for this class
#The work of this class is to decode and organize all the messages that we captured
class SSLStream():
    """
    Manage a SSLStream. Basically split tls_records retrieve handshake messages 
    to validate after through SSLVerificationDispatch.

    Remeber that we are validating in pasive mode that implies that the certificates 
    are captured later due to some connections over TCP are open until the user close 
    the tab. If we used libpcap when the flag "flush" appear we could process that message
    but we are using libnids and only we are listen when the connection is closed.
    That produce some delays in the verification process that could penalize the 
    performance in the whole software.
    """

    def __init__(self,raw_data,addr):
        self.addr = addr
        self._split_tls_records(raw_data)
        self._get_handshake_tls_records()
        self._process_handshake_messages()
        
    def _consistency_of_message(self,raw_data):
        """
        Basically we need to see if the length field match correctly.
        All this is due to the last message of handshake -finished- is encrypted
        to avoid false positive
        """
        #print util.hexdump(raw_data.decode('hex'))
        length = int(raw_data[2:8],16)
        next_byte = 8 + (length * 2)
        try:
            #Try access to it
            raw_data[next_byte-1]
            return True
        except:
            return False

        

#TODO create other file to process each message special focus in certificate message        
    def _process_handshake_messages(self):
       # Here we are gonna save all the data necessary to validate the authentication of the connection.
       # Since OCSP staplign is not widely deployed we will do everything trough certificatev
        data = {}
        for message in self._handshake_messages :
            #We are only interested in serverhello messages and certificate by now
            if message[10:12] == ssl_types.TLS_H_TYPE_SERVER_HELLO:
                if self._consistency_of_message(message[10:]):
                    pass
                
            elif message[10:12] == ssl_types.TLS_H_TYPE_CERTIFICATE:
                if self._consistency_of_message(message[10:]):
                    data['certificate'] = message
                    
            elif message[10:12] == ssl_types.TLS_H_TYPE_SERVER_KEY_EXCHANGE:
                if self._consistency_of_message(message[10:]):
                   pass 
               
            elif message[10:12] == ssl_types.TLS_H_TYPE_SERVER_HELLO_DONE:
                if self._consistency_of_message(message[10:]):
                   pass 
               
            elif message[10:12] == ssl_types.TLS_H_TYPE_CERTIFICATE_STATUS:
                if self._consistency_of_message(message[10:]):
                   # If you want save ocsp_stapling to verify the authentication
                   # you only should add to data['ocsp_stapling'] 
                    pass
            else:
                if not self._consistency_of_message(message[10:]):
                    pass
        SSLVerificationDispatch(data)
 
    def _get_handshake_tls_records(self):
        """
        Iterate over records to extract handshake messages
        """
        self._handshake_messages = list()
        for record in self._tls_records :
            #For each record we should determine if it is a hanshake message
            if record[0:2] == ssl_types.TLS_HANDSHAKE:
                self._handshake_messages.append(record)

    def _get_tls_version(self, data):
        """
        Method to print the version of TLS. Method for debug
        """
        if data[0:2] == '03':
            if data[2:4] == '00':
                return 'SSL 3.0'
            elif data[2:4] == '01':
                return 'TLS 1.0'
            elif data[2:4] == '02':
                return 'TLS 1.1'
            elif data[2:4] == '03':
                return 'TLS 1.2'
        else:
            return 'bad tls_version'
            
    def _split_tls_records(self,raw_data):
        """
        Raw_data may contain various tls_records. So for more analyse of them we need to split it
        """
        self._tls_records = list()
        s = raw_data.encode('hex')

        #Flag used to exit of bucle when we reach the final message of tls record
        end = 0
        while end == 0:
            #Here we assure that it is a valid tls record message
            if s[0:2] == ssl_types.TLS_HANDSHAKE or ssl_types.TLS_ALERT or ssl_types.TLS_APPLICATION \
                or ssl_types.TLS_CHANGE_CIPHER_SPEC or ssl_types.TLS_HEARBEAT:
                #It is a tls_record message valid

                #print self._get_tls_version(s[2:6])
                try:
                    length = int(s[6:10], 16)
                except:
                    #TODO Some times something happens here. 
                    print s
                next_record = 10 + (length * 2)
                #Maybe there is not a next_record we must access to it to see if a exception jump
                try:
                    s[next_record+1]
                except:
                    #We reach the final message
                    end = 1
                    return 
                self._tls_records.append(s[:next_record])
                s = s[next_record:]                    

        
