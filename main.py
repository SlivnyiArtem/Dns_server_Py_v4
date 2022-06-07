import pickle
import time

from dnslib import QTYPE, RR, A, AAAA, NS, PTR

from server_dns import DnsServer


def try_get_q_type(record_type_code):
    if record_type_code == 1:
        return A, QTYPE.A, "A"
    elif record_type_code == 28:
        return AAAA, QTYPE.AAAA, "AAAA"
    elif record_type_code == 2:
        return NS, QTYPE.NS, "NS"
    elif record_type_code == 12:
        return PTR, QTYPE.PTR, "PTR"


def load_cache(cache_file="cache.txt"):
    try:
        with open(cache_file, 'rb') as cache_file:
            cache = pickle.load(cache_file)
        return cache
    except FileNotFoundError:
        return Cache(60)
    except EOFError:
        return Cache(60)


class Cache:
    def __init__(self, res_rec_ttl):
        self.last_cache_update_time = time.time()
        self.res_rec_ttl = res_rec_ttl
        self.cache = {}
        for record_type in [1, 28, 2, 12]:
            self.cache[record_type] = {}

    def build_reply(self, packet_to_reply, name, reply_type):
        reply = packet_to_reply.reply()
        data_from_first = try_get_q_type(reply_type)[0](self.cache[reply_type][name][0])
        record_answer = RR(name, try_get_q_type(reply_type)[1], rdata=data_from_first, ttl=self.res_rec_ttl)
        reply.add_answer(record_answer)
        return reply.pack()

    def is_cache_contains(self, parsed_packet):
        record_name = str(parsed_packet.q.qname)
        record_type = parsed_packet.q.qtype
        return record_type in self.cache and record_name in self.cache[record_type]

    def cache_get_record(self, parsed_packet):
        record_name = str(parsed_packet.q.qname)
        record_type = parsed_packet.q.qtype
        return self.build_reply(parsed_packet, record_name, record_type)

    def add_record(self, record):
        self.cache[record.rtype][str(record.rname)] = (str(record.rdata), time.time(), record.ttl)

    def remove_exp_rec(self):
        for q_type in self.cache:
            temp_dict = self.cache[q_type]
            keys = []
            for q_name in temp_dict.keys():
                time_record_created = temp_dict[q_name][1]
                ttl = temp_dict[q_name][2]
                if time.time() - time_record_created > ttl:
                    keys.append(q_name)
            for key in keys:
                del temp_dict[key]
            self.cache[q_type] = temp_dict
        self.last_cache_update_time = time.time()

    def save_cache(self, cache_file="cache.txt"):
        with open(cache_file, 'wb+') as cache_file:
            pickle.dump(self, cache_file)


def main():
    cache = load_cache()
    cache.res_rec_ttl = 50

    try:
        DnsServer(cache, "localhost", 53).start()
    except (KeyboardInterrupt, SystemExit):
        cache.save_cache()


if __name__ == '__main__':
    main()
