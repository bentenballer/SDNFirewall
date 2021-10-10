import unittest
import time
from test_firewall_topo import OtherFWTopo
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, RemoteController
from mininet.util import custom
from mininet.link import TCLink
from mininet.cli import CLI


# TODO : Convert to Spring 2021 Test Cases and add to test.sh script
class OtherTestCase(unittest.TestCase):
    from tools import check_helper, check_icmp, check_connection

    @classmethod
    def setUpClass(self):
        topo = OtherFWTopo()
        self.net = Mininet(topo=topo, link=TCLink, controller=RemoteController("SDNFirewall", port=6633),
                           autoSetMacs=True)
        self.net.start()
        # self.net.pingPair()
        # self.net.pingAll(timeout=1)

    @classmethod
    def tearDownClass(self):
        self.net.stop()


    # Rule 1
    # Disallows ICMP to client1 from all computers
    # 1,Block,-,-,-,10.0.3.1/32,1,-,-,Blocks ICMP to client1 from all computers
    def test_rule_1(self):
        rules = [
            {"client": "w3", "server": "client1", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "w2", "server": "client1", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "w2", "server": "w3", "proto": "icmp", "retries": 1, "assert_value": True},
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 1 test case: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 2
    # Disallows TCP-1000 to client1 from all computers
    # 2,Block,-,-,-,10.0.3.1/32,6,-,10000,Blocks TCP-10000 to client1 from all computers
    def test_rule_2(self):
        rules = [
            {"client": "w3", "server": "client1", "port": 10000, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "w2", "server": "client1", "port": 10000, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "w2", "server": "w3", "port": 10000, "proto": "tcp", "retries": 1, "assert_value": True},
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 2 test case: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 3
    # Disallows UDP-2000 to client1 from all computers
    # 3,Block,-,-,-,10.0.3.1/32,17,-,20000,Blocks UDP-20000 to client1 from all computers
    def test_rule_3(self):
        rules = [
            {"client": "w3", "server": "client1", "port": 20000, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "w2", "server": "client1", "port": 20000, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "w2", "server": "w3", "port": 20000, "proto": "udp", "retries": 1, "assert_value": True},
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 3 test case: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 4
    # Disallows ICMP to server1 from all computers using dstmac
    # 4,Block,-,00:00:00:06:00:1e,-,-,1,-,-,Blocks ICMP to server1 from all computers using dstmac
    def test_rule_4(self):
        rules = [
            {"client": "w3", "server": "server1", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "w2", "server": "server1", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "w2", "server": "w3", "proto": "icmp", "retries": 1, "assert_value": True},
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 4 test case: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 5
    # Disallows ICMP from server2 from all computers using srcmac
    # 5,Block,00:00:00:07:01:1e,-,-,-,1,-,-,Blocks ICMP from server2 from all computers using srcmac
    def test_rule_5(self):
        rules = [
            {"client": "server2", "server": "w3", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "server2", "server": "w3", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "w2", "server": "w3", "proto": "icmp", "retries": 1, "assert_value": True},
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 5 test case: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 6
    # Disallows ICMP to server3 (dstmac) from e1 (ipaddr)
    # 6,Block,-,00:00:00:08:02:1e,10.0.0.1/32,-,1,-,-,Blocks ICMP to server3 (dstmac) from e1 (ipaddr)
    def test_rule_6(self):
        rules = [
            {"client": "e1", "server": "server3", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "e2", "server": "server3", "proto": "icmp", "retries": 1, "assert_value": True},
            {"client": "e1", "server": "w2", "proto": "icmp", "retries": 1, "assert_value": True},
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 6 test case: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 7
    # Disallows ICMP from w1 (srcmac) to e2 (ipaddr)
    # 7,Block,00:00:00:01:00:1e,-,-,10.0.0.2/32,1,-,-,Blocks ICMP from w1 (srcmac) to e2 (ipaddr)
    def test_rule_7(self):
        rules = [
            {"client": "w1", "server": "e2", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "w1", "server": "e3", "proto": "icmp", "retries": 1, "assert_value": True},
            {"client": "w1", "server": "w3", "proto": "icmp", "retries": 1, "assert_value": True},
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 7 test case: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 8
    # Blocks TCP from w1 (srcmac) port 80 to client1 (ipaddr) any destination port
    # 8,Block,00:00:00:01:00:1e,-,-,10.0.3.1/32,6,80,-,Blocks TCP from w1 port 80 to client 1 on any port
    def test_rule_8(self):
        rules = [
            {"client": "w1", "server": "client1", "port": 80, "source_port": 80, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "w1", "server": "client1", "port": 50, "source_port": 80, "proto": "tcp", "retries": 1, "assert_value": False},

            # this is false because while the original message might get to w1 port 80 the response from w1 80 won't make it back to ack
            {"client": "client1", "server": "w1", "port": 80, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "w1", "server": "client1", "port": 80, "source_port": 50, "proto": "tcp", "retries": 1, "assert_value": True},
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 8 test case: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 9 and 10
    # (9) Allows UDP port 53 from server2 (srcmac) to w3 (srcmac) first and then (10) blocks it -- check priority
    def test_rule_9(self):
        rules = [
            {"client": "server2", "server": "w3", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "w3", "server": "server2", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "server2", "server": "w3", "port": 80, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "server2", "server": "w3", "port": 53, "proto": "tcp", "retries": 1, "assert_value": True},
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 9/10 test case: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 11
    # (11) Blocks TCP port 73 from server2 (srcmac) to w3 (srcmac)
    def test_rule_10(self):
        rules = [
            {"client": "server2", "server": "w3", "port": 73, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "w3", "server": "server2", "port": 73, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "server2", "server": "w3", "port": 80, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "server2", "server": "w3", "port": 73, "proto": "udp", "retries": 1, "assert_value": True},
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 11 test case: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

if __name__ == '__main__':
    unittest.main()
