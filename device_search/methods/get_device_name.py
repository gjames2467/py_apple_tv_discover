import socket
import struct
from dnslib import DNSRecord


def _device_loop(sock, device_name, keep_looking=True):
    while keep_looking==True:
        try:
            m = sock.recvfrom(1024);  # print '%r'%m[0],m[1]

            dns = DNSRecord.parse(m[0])

            try:
                _device_name = dns.rr[0].rdata._label.idna()[:-1]
                if device_name.lower() in _device_name.lower():
                    # return DNSRecord.parse(m[0])
                    return _device_name
                    keep_looking = False
            except:
                pass

        except socket.timeout:
            return None
def _test_device_finder(device_name='appletv', service_type=['_tcp'],_socket_timeout=5):
    UDP_IP="0.0.0.0"
    UDP_PORT=5353
    MCAST_GRP = '224.0.0.251'
    sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind( (UDP_IP,UDP_PORT) )

    mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    for host in service_type:
         name = host+'.local'

         # dns = dpkt.dns.DNS('\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01')
         # print name
         # dns.qd[0].name=name
         dns_v2 = DNSRecord.parse('\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01'.encode('utf-8'))
         dns_v2=dns_v2.question(qname=name)


         sock.sendto(dns_v2.pack(),(MCAST_GRP,UDP_PORT))
    sock.settimeout(_socket_timeout)
    out_put_final_name=None
    while out_put_final_name==None:
        out_put_final_name=_device_loop(sock, device_name)
        _socket_timeout+=1
        sock.settimeout(_socket_timeout)


    return out_put_final_name


def device_finder(device_name='appletv', service_type=['_tcp'],_socket_timeout=5):
    UDP_IP="0.0.0.0"
    UDP_PORT=5353
    MCAST_GRP = '224.0.0.251'
    sock = socket.socket( socket.AF_INET, socket.SOCK_DGRAM )
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind( (UDP_IP,UDP_PORT) )

    mreq = struct.pack("4sl", socket.inet_aton(MCAST_GRP), socket.INADDR_ANY)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

    for host in service_type:
         name = host+'.local'

         # dns = dpkt.dns.DNS('\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01')
         # print name
         # dns.qd[0].name=name
         dns_v2 = DNSRecord.parse(str('\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x01').encode('utf-8'))
         dns_v2=dns_v2.question(qname=name)


         sock.sendto(dns_v2.pack(),(MCAST_GRP,UDP_PORT))
    sock.settimeout(_socket_timeout)
    out_put_final_name=None
    while out_put_final_name==None:
        out_put_final_name=_device_loop(sock, device_name)
        _socket_timeout+=1
        sock.settimeout(_socket_timeout)


    return out_put_final_name
