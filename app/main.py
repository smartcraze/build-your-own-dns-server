import socket
import struct
from dataclasses import dataclass

@dataclass
class DNSMessage:
    id: int
    qr: int
    opcode: int
    aa: int
    tc: int
    rd: int
    ra: int
    z: int
    rcode: int
    qdcount: int
    ancount: int
    nscount: int
    arcount: int

def create_header(qdcount=0, ancount=0):
    # Create a DNS header for the response
    return DNSMessage(
        id=1234,
        qr=1,        # 1 for response
        opcode=0,    # Standard query
        aa=0,        # Not authoritative
        tc=0,        # Not truncated
        rd=0,        # Recursion not desired
        ra=0,        # Recursion not available
        z=0,         # Reserved
        rcode=0,     # No error
        qdcount=qdcount,
        ancount=ancount,
        nscount=0,
        arcount=0,
    )

def pack_dns_message(message: DNSMessage) -> bytes:
    # Pack the DNS message header into bytes
    flags = (
        (message.qr << 15)
        | (message.opcode << 11)
        | (message.aa << 10)
        | (message.tc << 9)
        | (message.rd << 8)
        | (message.ra << 7)
        | (message.z << 4)
        | message.rcode
    )
    return struct.pack(
        ">HHHHHH",
        message.id,
        flags,
        message.qdcount,
        message.ancount,
        message.nscount,
        message.arcount,
    )

def parse_question_section(data: bytes) -> tuple:
    # Parse the question section to extract the domain name and query type
    domain_parts = []
    i = 0
    while data[i] != 0:
        length = data[i]
        i += 1
        domain_parts.append(data[i:i+length].decode("utf-8"))
        i += length
    domain_name = ".".join(domain_parts)
    qtype, qclass = struct.unpack(">HH", data[i+1:i+5])
    return domain_name, qtype, qclass

def create_answer_section() -> bytes:
    # Create a simple answer for the DNS query
    # Answer format: [Name, Type, Class, TTL, Data Length, Address]
    name = 0xC00C  # Pointer to the domain name in the question section
    rtype = 1      # Type A (host address)
    rclass = 1     # Class IN (Internet)
    ttl = 300      # Time to live (5 minutes)
    rdlength = 4   # Length of the address (4 bytes for IPv4)
    rdata = struct.pack(">BBBB", 127, 0, 0, 1)  # IP address: 127.0.0.1

    # Pack the answer
    return struct.pack(">HHHLH", name, rtype, rclass, ttl, rdlength) + rdata

def main():
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))
    print("UDP server is running on port 2053...")

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            if len(buf) < 12:
                print("Invalid packet")
                continue

            # Parse the question section
            question_section = buf[12:]
            domain_name, qtype, qclass = parse_question_section(question_section)
            print(f"Received query for domain: {domain_name}, type: {qtype}, class: {qclass}")

            # Create the response
            header = create_header(qdcount=1, ancount=1)
            response = pack_dns_message(header)
            response += buf[12:]  # Echo the question section back
            response += create_answer_section()  # Add the answer section

            # Send the response
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break

if __name__ == "__main__":
    main()
