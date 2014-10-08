

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


#All definitions of tls
#All values are express in hex


#RECORD LAYER PROTOCOL TYPE 
TLS_HANDSHAKE = '16'
TLS_ALERT = '15'
TLS_APPLICATION = '17'
TLS_HEARBEAT = '18'
TLS_CHANGE_CIPHER_SPEC = '14'


#HANDSHAKE MESSAGE TYPES
TLS_H_TYPE_HELLO_REQUEST = '00'
TLS_H_TYPE_CLIENT_HELLO = '01'
TLS_H_TYPE_SERVER_HELLO = '02'
TLS_H_TYPE_NEW_SESSION_TICKET = '04'
TLS_H_TYPE_CERTIFICATE = '0b'
TLS_H_TYPE_SERVER_KEY_EXCHANGE = '0c'
TLS_H_TYPE_CERTIFICATE_REQUEST =  '0d'
TLS_H_TYPE_SERVER_HELLO_DONE = '0e'
TLS_H_TYPE_CERTIFICATE_VERIFY =  '0f'
TLS_H_TYPE_CLIENT_KEY_EXCHANGE = '10'
TLS_H_TYPE_CERTIFICATE_STATUS = '16'

#We will never see this message because it will be encrypted
#but we can to deduce it 
TLS_H_TYPE_FINISHED = '14'
