"""Public-address DNS simulator confined to the disposable Docker test network."""
import socket
import struct

with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as sock:
    sock.bind(('198.41.0.4',53))
    while True:
        query,peer=sock.recvfrom(4096)
        if len(query)<12:
            continue
        offset=12
        while offset<len(query) and query[offset]:
            length=query[offset]
            if length>63:
                break
            offset+=1+length
        else:
            offset+=1
        if offset+4>len(query):
            continue
        qtype,qclass=struct.unpack('!HH',query[offset:offset+4])
        question=query[12:offset+4]
        if qtype==2:
            data=b'\x01a\x0croot-servers\x03net\0'
        elif qtype==1:
            data=socket.inet_aton('203.0.113.7')
        else:
            response=query[:2]+struct.pack('!5H',0x8180,1,0,0,0)+question
            sock.sendto(response,peer)
            continue
        response=query[:2]+struct.pack('!5H',0x8180,1,1,0,0)+question
        response+=b'\xc0\x0c'+struct.pack('!HHIH',qtype,qclass,60,len(data))+data
        sock.sendto(response,peer)
