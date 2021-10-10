import unittest
import time
from test_firewall_topo import FirewallTopo
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost, RemoteController
from mininet.util import custom
from mininet.link import TCLink
from mininet.cli import CLI


class YourTestCase(unittest.TestCase):
    from tools import check_helper, check_icmp, check_connection, check_gre

    @classmethod
    def setUpClass(self):
        topo = FirewallTopo()
        self.net = Mininet(topo=topo, link=TCLink, controller=RemoteController("SDNFirewall", port=6633),
                           autoSetMacs=True)
        self.net.start()

    @classmethod
    def tearDownClass(self):
        self.net.stop()

    #######################################################################################################
    #       Add '"debug": True' attribute to the Rule dictionaries below to turn on debug mode for a rule
    #######################################################################################################
    # Rule 1 - DNS hq1
    def test_rule_1(self):
        rules = [
            # UDP standard

            # hq1 - public
            {"client": "wo1", "server": "hq1", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "hq2", "server": "hq1", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "us1", "server": "hq1", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "cn1", "server": "hq1", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "in1", "server": "hq1", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "uk1", "server": "hq1", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},

            # hq2 - restricted to 5 corp networks
            # world
            {"client": "wo1", "server": "hq2", "port": 53, "proto": "udp", "retries": 1, "assert_value": False},
            # hq
            {"client": "hq1", "server": "hq2", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "hq5", "server": "hq2", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},

            # us
            {"client": "us1", "server": "hq2", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "us5", "server": "hq2", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},

            # in
            {"client": "in1", "server": "hq2", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "in5", "server": "hq2", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},

            # cn
            {"client": "cn1", "server": "hq2", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "cn5", "server": "hq2", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},

            # uk
            {"client": "uk1", "server": "hq2", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "uk5", "server": "hq2", "port": 53, "proto": "udp", "retries": 1, "assert_value": True},

            # TCP DNS-over-TLS
            # hq1 - public
            {"client": "wo1", "server": "hq1", "port": 853, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "hq2", "server": "hq1", "port": 853, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "us1", "server": "hq1", "port": 853, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "cn1", "server": "hq1", "port": 853, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "in1", "server": "hq1", "port": 853, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "uk1", "server": "hq1", "port": 853, "proto": "udp", "retries": 1, "assert_value": True},

            # hq2 - restricted to 5 corp networks
            # world
            {"client": "wo1", "server": "hq2", "port": 853, "proto": "tcp", "retries": 1, "assert_value": False},
            # hq
            {"client": "hq1", "server": "hq2", "port": 853, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "hq5", "server": "hq2", "port": 853, "proto": "tcp", "retries": 1, "assert_value": True},

            # us
            {"client": "us1", "server": "hq2", "port": 853, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "us5", "server": "hq2", "port": 853, "proto": "tcp", "retries": 1, "assert_value": True},

            # in
            {"client": "in1", "server": "hq2", "port": 853, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "in5", "server": "hq2", "port": 853, "proto": "tcp", "retries": 1, "assert_value": True},

            # cn
            {"client": "cn1", "server": "hq2", "port": 853, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "cn5", "server": "hq2", "port": 853, "proto": "tcp", "retries": 1, "assert_value": True},

            # uk
            {"client": "uk1", "server": "hq2", "port": 853, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "uk5", "server": "hq2", "port": 853, "proto": "tcp", "retries": 1, "assert_value": True},
        ]
        print("\nTesting Rule 1 - DNS")
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 1 test case: {}".format(rule))
            else:
                print("Passed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 2 - OpenVPN
    def test_rule_2(self):
        rules = [
            {"client": "wo1", "server": "hq3", "port": 1194, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "hq1", "server": "hq3", "port": 1194, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "us4", "server": "hq3", "port": 1194, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "in5", "server": "hq3", "port": 1194, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "uk2", "server": "hq3", "port": 1194, "proto": "tcp", "retries": 1, "assert_value": False},

            {"client": "wo1", "server": "hq3", "port": 1194, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "hq1", "server": "hq3", "port": 1194, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "us4", "server": "hq3", "port": 1194, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "in5", "server": "hq3", "port": 1194, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "uk2", "server": "hq3", "port": 1194, "proto": "udp", "retries": 1, "assert_value": False},

            #
            {"client": "us3", "server": "hq3", "port": 1194, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "in3", "server": "hq3", "port": 1194, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "cn3", "server": "hq3", "port": 1194, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "uk3", "server": "hq3", "port": 1194, "proto": "tcp", "retries": 1, "assert_value": True},

            {"client": "us3", "server": "hq3", "port": 1194, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "in3", "server": "hq3", "port": 1194, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "cn3", "server": "hq3", "port": 1194, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "uk3", "server": "hq3", "port": 1194, "proto": "udp", "retries": 1, "assert_value": True},

        ]
        print("\nTesting Rule 2 - OpenVPN")
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed:  Rule 2 test case: {}".format(rule))
            else:
                print("Passed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 3 - Ping
    def test_rule_3(self):
        rules = [
            # no one outside subnets can ping subnets
            {"client": "wo1", "server": "us1", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "cn2", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "in5", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "uk4", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "us1", "server": "hq3", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "us1", "server": "in4", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "cn1", "server": "uk3", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "us4", "server": "cn3", "proto": "icmp", "retries": 1, "assert_value": False},

            # World can access hq subnet
            {"client": "wo1", "server": "hq1", "proto": "icmp", "retries": 1, "assert_value": True},
            {"client": "wo1", "server": "hq5", "proto": "icmp", "retries": 1, "assert_value": True},

            # Subnets can access themselves
            {"client": "hq3", "server": "hq1", "proto": "icmp", "retries": 1, "assert_value": True},
            {"client": "us1", "server": "us5", "proto": "icmp", "retries": 1, "assert_value": True},
            {"client": "cn1", "server": "cn5", "proto": "icmp", "retries": 1, "assert_value": True},
            {"client": "in1", "server": "in5", "proto": "icmp", "retries": 1, "assert_value": True},
            {"client": "uk1", "server": "uk5", "proto": "icmp", "retries": 1, "assert_value": True},

            # "Definitive and final answer on Ping"
            # https://piazza.com/class/kie4njlr1ki6yg?cid=333_f50
            {"client": "us2", "server": "hq1", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "hq1", "server": "us1", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "us2", "server": "us1", "proto": "icmp", "retries": 1, "assert_value": True},
            {"client": "uk1", "server": "us1", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "hq1", "server": "hq5", "proto": "icmp", "retries": 1, "assert_value": True},
            {"client": "hq5", "server": "hq1", "proto": "icmp", "retries": 1, "assert_value": True},
            {"client": "wo1", "server": "hq1", "proto": "icmp", "retries": 1, "assert_value": True},
            {"client": "hq1", "server": "wo1", "proto": "icmp", "retries": 1, "assert_value": True},
            {"client": "wo1", "server": "us1", "proto": "icmp", "retries": 1, "assert_value": False},
            {"client": "us1", "server": "us2", "proto": "icmp", "retries": 1, "assert_value": True},
            {"client": "us1", "server": "uk1", "proto": "icmp", "retries": 1, "assert_value": False},

        ]
        print("\nTesting Rule 3 - PING")
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 3 test case: {}".format(rule))
            else:
                print("Passed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 4 - Remote Desktop
    def test_rule_4(self):
        rules = [
            # RDP UDP
            # world
            {"client": "wo1", "server": "us3", "port": 3389, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "in2", "port": 3389, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "cn3", "port": 3389, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "uk4", "port": 3389, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "hq2", "port": 3389, "proto": "udp", "retries": 1, "assert_value": False},

            # corp nets
            {"client": "hq1", "server": "cn4", "port": 3389, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "in1", "server": "uk3", "port": 3389, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "cn3", "server": "in1", "port": 3389, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "uk3", "server": "hq2", "port": 3389, "proto": "udp", "retries": 1, "assert_value": False},

            # RDP TCP
            # world
            {"client": "wo1", "server": "us3", "port": 3389, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "in5", "port": 3389, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "cn3", "port": 3389, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "uk4", "port": 3389, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "hq3", "port": 3389, "proto": "tcp", "retries": 1, "assert_value": False},

            # corp nets
            {"client": "hq1", "server": "cn4", "port": 3389, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "in1", "server": "uk3", "port": 3389, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "cn3", "server": "in1", "port": 3389, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "uk3", "server": "hq2", "port": 3389, "proto": "tcp", "retries": 1, "assert_value": False},

            # VNC TCP
            # world
            {"client": "wo1", "server": "us5", "port": 5900, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "in1", "port": 5900, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "cn4", "port": 5900, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "uk4", "port": 5900, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "wo1", "server": "hq2", "port": 5900, "proto": "tcp", "retries": 1, "assert_value": False},

            # corp nets
            {"client": "hq1", "server": "cn4", "port": 5900, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "in1", "server": "uk3", "port": 5900, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "cn3", "server": "in1", "port": 5900, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "uk3", "server": "hq2", "port": 5900, "proto": "tcp", "retries": 1, "assert_value": False},
        ]
        print("\nTesting Rule 4 - Remote Desktop")
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 4 test case: {}".format(rule))
            else:
                print("Passed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 5 - Microservice TCP/UDP Port 8500 on us3 and us4
    def test_rule_5(self):
        rules = [
            # UDP
            # world and other subs
            {"client": "wo1", "server": "us3", "port": 8500, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "wo1", "server": "us4", "port": 8500, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "uk1", "server": "us3", "port": 8500, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "cn3", "server": "us4", "port": 8500, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "us1", "server": "us3", "port": 8500, "proto": "udp", "retries": 1, "assert_value": True},
            {"client": "cn1", "server": "us4", "port": 8500, "proto": "udp", "retries": 1, "assert_value": True},

            # uk2, uk3, uk4, uk5, in4, in5, us5, and hq5
            {"client": "uk2", "server": "us3", "port": 8500, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "uk3", "server": "us4", "port": 8500, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "uk4", "server": "us3", "port": 8500, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "uk5", "server": "us4", "port": 8500, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "in4", "server": "us3", "port": 8500, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "in5", "server": "us3", "port": 8500, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "us5", "server": "us3", "port": 8500, "proto": "udp", "retries": 1, "assert_value": False},
            {"client": "hq5", "server": "us4", "port": 8500, "proto": "udp", "retries": 1, "assert_value": False},

            # TCP
            # world and other subs
            {"client": "wo1", "server": "us3", "port": 8500, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "wo1", "server": "us4", "port": 8500, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "uk1", "server": "us3", "port": 8500, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "cn3", "server": "us4", "port": 8500, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "us1", "server": "us3", "port": 8500, "proto": "tcp", "retries": 1, "assert_value": True},
            {"client": "cn1", "server": "us4", "port": 8500, "proto": "tcp", "retries": 1, "assert_value": True},

            # uk2, uk3, uk4, uk5, in4, in5, us5, and hq5
            {"client": "uk2", "server": "us3", "port": 8500, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "uk3", "server": "us4", "port": 8500, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "uk4", "server": "us3", "port": 8500, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "uk5", "server": "us4", "port": 8500, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "in4", "server": "us3", "port": 8500, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "in5", "server": "us3", "port": 8500, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "us5", "server": "us3", "port": 8500, "proto": "tcp", "retries": 1, "assert_value": False},
            {"client": "hq5", "server": "us4", "port": 8500, "proto": "tcp", "retries": 1, "assert_value": False},

        ]
        print("\nTesting Rule 5 - Microservice TCP/UDP Port 8500")
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 5 test case: {}".format(rule))
            else:
                print("Passed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 6 - NetBIOS over TCPIP
    def test_rule_6(self):
        rules = [
            # TCP
            {"client": "wo1", "server": "hq3", "port": 137, "proto": "tcp", "assert_value": False},
            {"client": "wo1", "server": "us3", "port": 137, "proto": "tcp", "assert_value": False},
            {"client": "wo1", "server": "cn3", "port": 139, "proto": "tcp", "assert_value": False},
            {"client": "wo1", "server": "in2", "port": 137, "proto": "tcp", "assert_value": False},
            {"client": "hq1", "server": "uk4", "port": 137, "proto": "tcp", "assert_value": False},
            {"client": "us1", "server": "us3", "port": 139, "proto": "tcp", "assert_value": False},
            {"client": "uk1", "server": "uk5", "port": 139, "proto": "tcp", "assert_value": False},
            {"client": "in1", "server": "cn3", "port": 139, "proto": "tcp", "assert_value": False},
            {"client": "cn1", "server": "cn3", "port": 139, "proto": "tcp", "assert_value": False},

            # UDP
            {"client": "wo1", "server": "hq3", "port": 137, "proto": "udp", "assert_value": False},
            {"client": "wo1", "server": "us2", "port": 137, "proto": "udp", "assert_value": False},
            {"client": "wo1", "server": "cn4", "port": 138, "proto": "udp", "assert_value": False},
            {"client": "wo1", "server": "in3", "port": 137, "proto": "udp", "assert_value": False},
            {"client": "us1", "server": "hq2", "port": 138, "proto": "udp", "assert_value": False},
            {"client": "uk1", "server": "in3", "port": 138, "proto": "udp", "assert_value": False},
            {"client": "in1", "server": "cn2", "port": 138, "proto": "udp", "assert_value": False},
            {"client": "cn1", "server": "cn5", "port": 138, "proto": "udp", "assert_value": False},

        ]
        print("\nTesting Rule 6 - NetBIOS over IP")
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 6 test case: {}".format(rule))
            else:
                print("Passed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 7 - Block GRE Protocol - 47
    def test_rule_7(self):
        rules = [
            {"client": "wo1", "server": "hq3", "proto": "gre", "assert_value": False},
            {"client": "wo1", "server": "cn3", "proto": "gre", "assert_value": False},
            {"client": "wo1", "server": "in3", "proto": "gre", "assert_value": False},
            {"client": "wo1", "server": "us3", "proto": "gre", "assert_value": False},
            {"client": "wo1", "server": "uk2", "proto": "gre", "assert_value": False},
            {"client": "uk1", "server": "hq3", "proto": "gre", "assert_value": False},
            {"client": "in1", "server": "cn4", "proto": "gre", "assert_value": False},
            {"client": "us1", "server": "us3", "proto": "gre", "assert_value": False},
            {"client": "cn2", "server": "uk4", "proto": "gre", "assert_value": False},

        ]
        print("\nTesting Rule 7 - GRE IP Protocol")
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: Rule 7 test case: {}".format(rule))
            else:
                print("Passed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))


if __name__ == '__main__':
    unittest.main()
