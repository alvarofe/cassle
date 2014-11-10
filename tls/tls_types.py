

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
TLS_HANDSHAKE = 22
TLS_ALERT = 21
TLS_APPLICATION = 23
TLS_HEARBEAT = 24
TLS_CHANGE_CIPHER_SPEC = 20


#HANDSHAKE MESSAGE TYPES
TLS_H_TYPE_HELLO_REQUEST = 0
TLS_H_TYPE_CLIENT_HELLO = 1
TLS_H_TYPE_SERVER_HELLO = 2
TLS_H_TYPE_NEW_SESSION_TICKET = 4
TLS_H_TYPE_CERTIFICATE = 11
TLS_H_TYPE_SERVER_KEY_EXCHANGE = 12
TLS_H_TYPE_CERTIFICATE_REQUEST =  13
TLS_H_TYPE_SERVER_HELLO_DONE = 14
TLS_H_TYPE_CERTIFICATE_VERIFY =  15
TLS_H_TYPE_CLIENT_KEY_EXCHANGE = 16
TLS_H_TYPE_CERTIFICATE_STATUS = 22

#We will never see this message because it will be encrypted
#but we can to deduce it 
TLS_H_TYPE_FINISHED = 24
