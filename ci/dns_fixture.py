"""Public-address DNS simulator confined to the disposable Docker test network."""
import socket
import struct

with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
    sock.bind(('9.9.9.9',53))
    while True:
        query,peer=sock.recvfrom(4096)
        if len(query)<12:
            continue
        response=query[:2]+struct.pack('!5H',0x8180,1,1,0,0)+query[12:]
        response+=b'\xc0\x0c'+struct.pack('!HHIH',1,1,60,4)+socket.inet_aton('203.0.113.7')
        sock.sendto(response,peer)
