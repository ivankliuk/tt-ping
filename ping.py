import re
import threading
import unittest

import netinfo
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from settings import DEST_IP, PACKET_COUNT, TIMEOUT


lock = threading.Lock()

# Helper functions
def first_eth_iface():
    for i in netinfo.list_active_devs():
        if re.match('^eth\w+$', i):
            return i
    raise Exception('No ethX interfaces found in the system!')


def default_iface():
    for rec in netinfo.get_routes():
        if rec['dest'] == '0.0.0.0':
            return rec['dev']
    raise Exception('No default gateway is configured!')


# Base classes
class BasePing(threading.Thread):
    def __init__(self, dest_ip, outgoing_iface, packet_count):
        super(BasePing, self).__init__()
        self.dest_ip = dest_ip
        self.outgoing_iface = outgoing_iface
        self.packet_count = packet_count

    def run(self):
        raise NotImplemented


class BaseSniff(threading.Thread):
    def __init__(self, dest_ip, outgoing_iface, packet_count):
        super(BaseSniff, self).__init__()
        self.outgoing_iface = outgoing_iface
        self.packet_count = packet_count
        src_ip = netinfo.get_ip(outgoing_iface)
        self.filter = "icmp and src host %s and dst host %s" % (src_ip, dest_ip)
        self.sent = 0

    def run(self):
        raise NotImplemented


# Task based classes
class Ping(BasePing):
    def run(self):
        send(IP(src=netinfo.get_ip(self.outgoing_iface), dst=DEST_IP) / ICMP(),
             iface=self.outgoing_iface,
             count=self.packet_count,
             verbose=False)


class Sniff(BaseSniff):
    def run(self):
        self.sent = len(sniff(filter=self.filter,
                              count=self.packet_count,
                              timeout=TIMEOUT))


class SniffSync(Sniff):
    def __init__(self, dest_ip, outgoing_iface, packet_count, results):
        super(Sniff, self).__init__(dest_ip, outgoing_iface, packet_count)
        self.results = results

    def run(self):
        super(SniffSync, self).run()
        with lock:
            self.results[self.outgoing_iface] = self.sent


class PingDefault(BasePing):
    def __init__(self, dest_ip, outgoing_iface, packet_count):
        super(PingDefault, self).__init__(dest_ip, outgoing_iface, packet_count)
        self.recieved = 0

    def run(self):
        for i in xrange(self.packet_count):
            ans, unans = sr(IP(dst=self.dest_ip) / ICMP(),
                            iface=self.outgoing_iface,
                            verbose=False)
            if ans:
                self.recieved += 1


# Testing implementation
class TestTask(unittest.TestCase):
    def test_task_1(self):
        args = [DEST_IP, first_eth_iface(), PACKET_COUNT]
        snff = Sniff(*args)
        ping = Ping(*args)
        snff.start()
        ping.start()

        for t in (snff, ping):
            t.join()

        self.assertEqual(PACKET_COUNT, snff.sent)

    def test_task_2(self):
        results = dict()

        args1 = [DEST_IP, 'lo', PACKET_COUNT]
        ping1 = Ping(*args1)
        args1.append(results)
        sniff1 = SniffSync(*args1)

        args2 = [DEST_IP, first_eth_iface(), PACKET_COUNT]
        ping2 = Ping(*args2)
        args2.append(results)
        sniff2 = SniffSync(*args2)

        threads = [sniff1, sniff2, ping1, ping2]

        for t in threads:
            t.start()

        for t in threads:
            t.join()
        for k, v in results.iteritems():
            self.assertEqual(PACKET_COUNT, v)

    def test_task_3(self):
        results = dict()
        threads = list()

        for iface in netinfo.list_active_devs():
            args = [DEST_IP, iface, PACKET_COUNT, results]
            threads.append(SniffSync(*args))
            args.pop()
            threads.append(Ping(*args))

        for t in threads:
            t.start()

        for t in threads:
            t.join()

        for k, v in results.iteritems():
            self.assertEqual(PACKET_COUNT, v)

    def test_task_4(self):
        args = [DEST_IP, default_iface(), PACKET_COUNT]
        ping = PingDefault(*args)
        ping.start()
        ping.join()
        self.assertEqual(PACKET_COUNT, ping.recieved)


if __name__ == "__main__":
    unittest.main()
