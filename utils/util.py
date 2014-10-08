

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


import struct
import socket
# import pcap
from tls import tls_types
from pprint import pprint



#The code for hexdump was extracted from dpkt source code
__vis_filter = """................................ !"#$%&\'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[.]^_`abcdefghijklmnopqrstuvwxyz{|}~................................................................................................................................."""

def hexdump(buf, length=16):
    """Return a hexdump output string of the given buffer."""
    n = 0
    res = []
    while buf:
        line, buf = buf[:length], buf[length:]
        hexa = ' '.join(['%02x' % ord(x) for x in line])
        line = line.translate(__vis_filter)
        res.append('  %04d:  %-*s %s' % (n, length * 3, hexa, line))
        n += length
    return '\n'.join(res)

def decode_packet(pktlen, datos, timestamp):
    if not datos:
        return
    if datos[12:14] == '\x08\x00':
        packet = datos[14:]
        ip_header = packet[0:20]
     
        """
        The ip_headers looks like 

        typedef struct header
        {
        //IP-Header
            unsigned char ip_v:4, ip_hl:4;/* this means that each member is 4 bits */
            unsigned char ip_tos;       //1 Byte
            unsigned short int ip_len;  //2 Byte
            unsigned short int ip_id;   //2 Byte
            unsigned short int ip_off;  //2 Byte
            unsigned char ip_ttl;       //1 Byte
            unsigned char ip_p;         //1 Byte
            unsigned short int ip_sum;  //2 Byte
            unsigned int ip_src;        //4 Byte
            unsigned int ip_dst;        //4 Byte
        }   
        """
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
        version_ihl = iph[0]
        version = version_ihl >> 4
        ihl = version_ihl & 0xF
        iph_length = ihl * 4  
        ttl = iph[5]
        protocol = iph[6]
        s_addr = socket.inet_ntoa(iph[8]);
        d_addr = socket.inet_ntoa(iph[9]);
         
        # print 'Version : ' + str(version) + ' IP Header Length : ' + str(ihl) + ' TTL : ' + str(ttl) + ' Protocol : ' + str(protocol) + ' Source Address : ' + str(s_addr) + ' Destination Address : ' + str(d_addr)

        tcp_header = packet[iph_length:iph_length+20]
         
        """
        TCP headers looks like

        typedef struct {
              uint16_t src_port;
              uint16_t dst_port;
              uint32_t seq;
              uint32_t ack;
              uint8_t  data_offset;  // 4 bits
              uint8_t  flags;
              uint16_t window_size;
              uint16_t checksum;
              uint16_t urgent_p;
        } tcp_header_t;
        """

        tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
        source_port = tcph[0]
        dest_port = tcph[1]
        sequence = tcph[2]
        acknowledgement = tcph[3]
        doff_reserved = tcph[4]
        flag = tcph[5]
        tcph_length = doff_reserved >> 4
         
        # print 'Source Port : ' + str(source_port) + ' Dest Port : ' + str(dest_port) + ' Sequence Number : ' + str(sequence) + ' Acknowledgement : ' + str(acknowledgement) + ' TCP header length : ' + str(tcph_length) + ' Flag: ' + str(flag)
         
        h_size = iph_length + tcph_length * 4
        data_size = len(packet) - h_size
         
        #get data from the packet
        data = packet[h_size:]
        assembler(data.encode('hex'), s_addr, d_addr, source_port, dest_port,flag, str(sequence))


def is_server_hello_message(data):
    if data[0:2] == tls_types.TLS_HANDSHAKE and data[10:12] == tls_types.TLS_H_TYPE_SERVER_HELLO:
        return True
    else:
        return False
def is_alert_message(data):
    if data[0:2] == tls_types.TLS_ALERT and (data[2:6] == '0303' or data[2:6] == '0301'):
        return True
    else:
        return False


metadata = dict()

def assembler(data,s_addr, d_addr, source_port, dest_port, flag, sequence):
    """
    Function that assembles all the packets to produce a stream of tls. But we start to assembles it when serverHello o alertMessage is seen

    Parameters:
        -data : The TCP data encode in hex. This is because then is more easy manipulate the data
        -s_addr : The src IP 
        -d_addr : The dst IP 
        -source_port : The src port
        -dest_port : The dest port
        -flag: The TCP flag of our tcp packet
        -sequence: The seq of our tcp packet
    """

    global metadata
    src = str(s_addr)
    dst = str(d_addr)
    sport = str(source_port)
    dport = str(dest_port)
    recollect = False

    
    id = (src,dst,sport,dport)
    try:
        recollect = metadata[id]['recollect']
    except KeyError:
        recollect = False
        
    if flag == 16:
        #16 means ACK
        if recollect == True:
            metadata[id]['data'][sequence] = data.decode('hex')
        elif is_server_hello_message(data) or is_alert_message(data):
            # We start collect data when a new connection is seen. Usually all the connection start with Server Hello message. 
            # I put also Alert Message bacause some certificates come after this message. I saw this through wireshark
            metadata[id] = dict()
            metadata[id]['data'] = dict()
            metadata[id]['recollect'] = True # That True says that with that id we can put data in it
            metadata[id]['psh-ack'] = 0 # The psh-ack is used as a flag to terminate the recollecting of data. After two psh-ack we already have the certificate message 
                                        # so we don't need to recollect more data
            metadata[id]['data'][sequence] = data.decode('hex')
    if flag == 24:
        #24 means PSH-ACK
        if recollect == True:
            if metadata[id]['psh-ack'] != 2:
                metadata[id]['psh-ack'] += 1
                metadata[id]['data'][sequence] = data.decode('hex')
            else:
                #Second PSH-ACK received
                metadata[id]['data'][sequence] = data.decode('hex')
                stream = metadata[id]['data']
                process_stream(stream)
                del (metadata[id])


def process_stream(tls_stream):
    #To break import loop
    from tls.tls_stream import TLSStream
    TLSStream(tls_stream)
    # aux = str()
    # for key in sorted(tls_stream):
    #     aux += tls_stream[key]
    # print hexdump(aux)


