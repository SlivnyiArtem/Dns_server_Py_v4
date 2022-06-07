import time
from _socket import timeout
from socket import AF_INET, SOCK_DGRAM, socket
from dnslib import DNSRecord


class DnsServer:
    def __init__(self, cache_data,  host_name, port, ttl=50, server_timeout=5):
        self.ttl = ttl
        self.cache_data = cache_data
        self.server_timeout = server_timeout
        self.host_name = host_name
        self.port = port
        self.socket = socket(AF_INET, SOCK_DGRAM)
        self.socket.bind((self.host_name, self.port))
        self.socket.settimeout(self.server_timeout)

    def start(self):
        while True:
            data, address = self.receive_data()
            try:
                self.socket.sendto(self.handle_packet(data), address)
            except LookupError:
                print("Неизвестное доменное имя или для этого имени не существует искомых записей")
            if self.ttl < time.time() - self.cache_data.last_cache_update_time:
                self.cache_data.remove_exp_rec()

    def receive_data(self):
        try:
            return self.socket.recvfrom(256)
        except timeout:
            return self.receive_data()
        except KeyboardInterrupt:
            self.socket.close()
            exit()

    def handle_packet(self, package: bytes) -> bytes:
        response_server_ip = "8.8.8.8"
        res_response = None
        dns_record_response = None
        while dns_record_response is None or len(dns_record_response.rr) == 0:
            parsed_packet = DNSRecord.parse(package)
            if self.cache_data.is_cache_contains(parsed_packet):
                cache_record = self.cache_data.cache_get_record(parsed_packet)
                return cache_record
            try:
                res_response = parsed_packet.send(response_server_ip)
            except timeout:
                continue
            dns_record_response = DNSRecord.parse(res_response)
            if dns_record_response.header.rcode == 3:
                return res_response
            for record in dns_record_response.ar:
                self.cache_data.add_record(record)
            response_server_ip = next((str(x.rdata) for x in dns_record_response.ar if x.rtype == 1), -1)
            if response_server_ip == -1 and len(dns_record_response.rr) == 0:
                resp = self.handle_packet(DNSRecord.question(str(dns_record_response.auth[0].rdata)).pack())
                resource_records = DNSRecord.parse(resp).rr
                if len(resource_records) > 0:
                    response_server_ip = str(DNSRecord.parse(resp).rr[0].rdata)
                if response_server_ip == -1:
                    raise KeyError
        for record in dns_record_response.rr:
            self.cache_data.add_record(record)
        return res_response
