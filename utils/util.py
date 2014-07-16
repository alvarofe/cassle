###############################################################################################
### Name: util.py
### Author: Alvaro Felipe Melchor - alvaro.felipe91@gmail.com
### Twitter : @alvaro_fe
### University of Alcala de Henares
###############################################################################################

import struct
import socket
import pcap
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


#In pkt we're gonna save all the packets to then reassembly it
pkt = dict()

#Basically here is a boolean for each "session" to determine when to process all the packetes
#saved in pkt
psh = dict()

def decode_ip_packet(s):
    d = {
            'version': (ord(s[0]) & 0xf0) >> 4,
            'header_len': ord(s[0]) & 0x0f,
            'tos': ord(s[1]),
            'total_len': socket.ntohs(struct.unpack('H', s[2:4])[0]),
            'id': socket.ntohs(struct.unpack('H', s[4:6])[0]),
            'flags': (ord(s[6]) & 0xe0) >> 5,
            'fragment_offset': socket.ntohs(struct.unpack('H', s[6:8])[0] & 0x1f),
            'ttl': ord(s[8]),
            'protocol': ord(s[9]),
            'checksum': socket.ntohs(struct.unpack('H', s[10:12])[0]),
            'source_address': pcap.ntoa(struct.unpack('i', s[12:16])[0]),
            'destination_address': pcap.ntoa(struct.unpack('i', s[16:20])[0])
        }
    if d['header_len'] > 5:
        d['options'] = s[20:4 * (d['header_len'] - 5)]
    else:
        d['options'] = None
    d['data'] = s[4 * d['header_len']:]
    return d


def decode_tcp_packet(s):
    d = {
            'sport': socket.ntohs(struct.unpack('H', s[0:2])[0]),
            'dport': socket.ntohs(struct.unpack('H', s[2:4])[0]),
            'seq': socket.ntohl(struct.unpack('I', s[4:8])[0]),
            'ack': socket.ntohl(struct.unpack('I', s[8:12])[0]),
            'dataof': (ord(s[12]) & 0xe0) >> 5,
            'flag': (socket.ntohs(struct.unpack('H', s[12:14])[0]) & 511),
            'ws': socket.ntohs(struct.unpack('H', s[14:16])[0]),
            'checksum': socket.ntohs(struct.unpack('H', s[16:18])[0]),
            'urgp': socket.ntohs(struct.unpack('H', s[18:20])[0])
        }
    d['data'] = s[4 * d['dataof']:]
    return d


def decode_packet(pktlen, datos, timestamp):
    if not datos:
        return
    if datos[12:14] == '\x08\x00':
        ip = decode_ip_packet(datos[14:])
        tcp = decode_tcp_packet(ip['data'])
        reassembler(tcp, ip)

def is_server_hello_message(data):
    if data[0:2] == tls_types.TLS_HANDSHAKE and data[10:12] == tls_types.TLS_H_TYPE_SERVER_HELLO:
        return True
    else:
        return False

def is_alert_message(data):
    if data[0:2] == tls_types.TLS_ALERT and data[2:6] == '0303':
        return True
    else:
        return False


metadata = dict()

def reassembler(tcp,ip):
    global metadata
    src = ip['source_address']
    dst = ip['destination_address']
    sport = str(tcp['sport'])
    dport = str(tcp['dport'])
    data = (tcp['data'].encode('hex')[32:])
    #print hexdump(data)
    flag = tcp['flag']

    try:
        id = (src,dst,sport,dport)
        if flag == 16:
            #16 means ACK
            try:
                flag = metadata[id]['recollect']
            except KeyError:
                flag = False
            if flag == True:
                metadata[id]['data'][str(tcp['seq'])] = data.decode('hex')
            elif is_server_hello_message(data) or is_alert_message(data):
                #We start collect data
                metadata[id] = dict()
                metadata[id]['data'] = dict()
                metadata[id]['recollect'] = True
                metadata[id]['psh-ack'] = 0
                metadata[id]['data'][str(tcp['seq'])] = data.decode('hex')
        if flag == 24:
            #24 means PSH-ACK
            try:
                if metadata[id]['recollect'] == True:
                    if metadata[id]['psh-ack'] != 2:
                        metadata[id]['psh-ack'] += 1
                        metadata[id]['data'][str(tcp['seq'])] = data.decode('hex')
                    else:
                        #Second PSH-ACK received
                        metadata[id]['data'][str(tcp['seq'])] = data.decode('hex')
                        process(metadata[id]['data'])
                        del (metadata[id])
            except:
                pass

    except:
            pass

    #TODO improve this
    #try:
        #tupl = (src, dst, sport, dport)
        #if flag == 18 or ((flag & 2) >> 1) == 1:

            ##If flag == 18 means that flags SYNC and URG are activate new connection was established
            ##(flag & 2) >> 1 is to see if the flag SYNC is presented
            #pkt[tupl] = dict()  #In this dictionary we are gonna saved all the packets that match that tupl
            #psh[tupl] = False #Indicate if we must process the packet

        #elif flag == 11 or flag & 1 == 1:
            ##SYNC/ACK/FIN or FIN was received
            #process(pkt[tupl])
            #del (pkt[tupl])
            ##if we receive a 24 and before we received server hello don't care I am only interested in 24 after see a certificate
        #elif flag == 24:
            ##URG/ACK was received we must send to process because is data urgent so we can retrieve the TLS certificate in real time
            #if tupl in pkt:
                #pkt[tupl][str(tcp['seq'])] = data
                #if psh[tupl] == True:
                    #process(pkt[tupl])
                    #del (pkt[tupl])
                #elif psh[tupl] == False:
                    #psh[tupl] = True
        #else:
            #if tupl in pkt:
                #if psh[tupl] == True:
                    #process(pkt[tupl])
                    #del (pkt[tupl])
                #pkt[tupl][str(tcp['seq'])] = data
    #except KeyError:
        #pass


def process(tls_stream):
    #To break import loop
    from tls.tls_stream import TLSStream
    TLSStream(tls_stream)
    #aux = str()
    #for key in sorted(tls_stream):
        #aux += tls_stream[key]
    #print hexdump(aux)


