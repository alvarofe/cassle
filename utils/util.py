###############################################################################################
### Name: util.py
### Author: Alvaro Felipe Melchor - alvaro.felipe91@gmail.com
### Twitter : @alvaro_fe
### University of Alcala de Henares
###############################################################################################

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

protocols = {socket.IPPROTO_TCP: 'tcp', socket.IPPROTO_UDP: 'udp', socket.IPPROTO_ICMP: 'icmp'}
def decode_packet(pktlen, datos, timestamp):
    if not datos:
        return
    if datos[12:14] == '\x08\x00':
        packet = datos[14:]
        ip_header = packet[0:20]
     
        #now unpack them :)
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
         
        #now unpack them :)
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
            #We start collect data
            metadata[id] = dict()
            metadata[id]['data'] = dict()
            metadata[id]['recollect'] = True
            metadata[id]['psh-ack'] = 0
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
                # print stream
                from tls.tls_stream import TLSStream
                TLSStream(stream)
                del (metadata[id])
                # process_stream(id)
                       

    


def process_stream(id):
    #To break import loop
    tls_stream = metadata[id]['data']
    del (metadata[id])
    # from tls.tls_stream import TLSStream
    # TLSStream(tls_stream)
    aux = str()
    for key in sorted(tls_stream):
        aux += tls_stream[key]
    print hexdump(aux)


