import unittest
import time
from test_firewall_topo import OtherFWTopo
from mininet.topo import Topo
from mininet.net  import Mininet
from mininet.node import CPULimitedHost, RemoteController
from mininet.util import custom
from mininet.link import TCLink
from mininet.cli  import CLI

# TODO : Convert to Spring 2021 Test Cases and add to test.sh script
class GoodTestCase(unittest.TestCase):
    from tools import check_helper, check_icmp, check_connection

    @classmethod
    def setUpClass(self):
        topo = OtherFWTopo()
        self.net = Mininet(topo=topo, link=TCLink, controller=RemoteController("SDNFirewall",port=6633), autoSetMacs=True)
        self.net.start()
        #self.net.pingPair()
        #self.net.pingAll(timeout=1)

    @classmethod
    def tearDownClass(self):
        self.net.stop()

    # This is the only rule in firewall-policies-good, tcp 1080 should fail, udp should succeed, tcp 1081 should work
    def test_firewall_policies_good(self):
        rules = [ 
            { "client": "e1", "server": "e2", "port": 1080, "proto": "tcp", "retries": 1, "assert_value": False },
            { "client": "e1", "server": "e2", "port": 1080, "proto": "udp", "retries": 1, "assert_value": True  },
            { "client": "e1", "server": "e2", "port": 1723, "proto": "tcp", "retries": 1, "assert_value": True  },
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 1 - PPTP
    def test_rule_1(self):
        rules = [ 
            #{ "client": "e1", "server": "server2", "port": 1723, "proto": "tcp", "retries": 1, "debug": True, "assert_value": True  },
            { "client": "e1", "server": "server2", "port": 1723, "proto": "tcp", "retries": 1, "assert_value": True  },
            { "client": "e2", "server": "server2", "port": 1723, "proto": "tcp", "retries": 1, "assert_value": True  },
            { "client": "w1", "server": "server2", "port": 1723, "proto": "tcp", "retries": 1, "assert_value": True  },
            { "client": "e1", "server": "server1", "port": 1723, "proto": "tcp", "retries": 1, "assert_value": True  },
            { "client": "e1", "server": "server2", "port": 1723, "proto": "udp", "retries": 1, "assert_value": True  },
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))


    # Rule 2 - SSH
    def test_rule_2(self):
        rules = [ 
            { "client": "w1", "server": "e1", "port": 22, "proto": "tcp", "retries": 1, "assert_value": True  },
            { "client": "w1", "server": "e2", "port": 22, "proto": "tcp", "retries": 1, "assert_value": True  },
            { "client": "w1", "server": "e3", "port": 22, "proto": "tcp", "retries": 1, "assert_value": True  },
            { "client": "e1", "server": "e3", "port": 22, "proto": "tcp", "retries": 1, "assert_value": True  },
            { "client": "e1", "server": "w1", "port": 22, "proto": "tcp", "retries": 1, "assert_value": True  },
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 3 - NTP / DNS
    def test_rule_3(self):
        rules = [
            { "client": "e1", "server": "server1", "port": 53,  "proto": "udp", "retries": 1, "assert_value": True  },
            { "client": "w1", "server": "server1", "port": 53,  "proto": "udp", "retries": 1, "assert_value": True  },
            { "client": "e1", "server": "server2", "port": 53,  "proto": "udp", "retries": 1, "assert_value": True  },
            { "client": "w1", "server": "server2", "port": 53,  "proto": "udp", "retries": 1, "assert_value": True  },
            { "client": "e1", "server": "server1", "port": 123, "proto": "udp", "retries": 1, "assert_value": True  },
            { "client": "w1", "server": "server1", "port": 123, "proto": "udp", "retries": 1, "assert_value": True  },
            { "client": "e1", "server": "server2", "port": 123, "proto": "udp", "retries": 1, "assert_value": True  },
            { "client": "w1", "server": "server2", "port": 123, "proto": "udp", "retries": 1, "assert_value": True  },
            { "client": "e1", "server": "server3", "port": 123, "proto": "udp", "retries": 1, "assert_value": True  },
            { "client": "w1", "server": "server3", "port": 123, "proto": "udp", "retries": 1, "assert_value": True  },
            { "client": "e1", "server": "server3", "port": 53,  "proto": "udp", "retries": 1, "assert_value": True  },
            { "client": "e1", "server": "server3", "port": 53,  "proto": "udp", "retries": 1, "assert_value": True  },
            { "client": "e1", "server": "server1", "port": 53,  "proto": "tcp", "retries": 1, "assert_value": True  },
            { "client": "e1", "server": "server2", "port": 53,  "proto": "tcp", "retries": 1, "assert_value": True  },
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 4 - ICMP 
    def test_rule_4(self):
        rules = [
            #{ "client": "w1", "server": "client1", "proto": "icmp", "retries": 1, "debug": True, "assert_value": True  },
            { "client": "w1", "server": "client1", "proto": "icmp", "retries": 1, "assert_value": True  },
            { "client": "w2", "server": "client1", "proto": "icmp", "retries": 1, "assert_value": True  },
            { "client": "w1", "server": "e1",      "proto": "icmp", "retries": 1, "assert_value": True  },
            { "client": "w2", "server": "e1",      "proto": "icmp", "retries": 1, "assert_value": True  },
            { "client": "w1", "server": "w2",      "proto": "icmp", "retries": 1, "assert_value": True  },
            { "client": "w3", "server": "client1", "proto": "icmp", "retries": 1, "assert_value": True  },
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 5 - e1 -> e3 tcp 9950-9952
    def test_rule_5(self):
        rules = [
            { "client": "e1", "server": "e3", "port": 9950, "proto": "tcp", "retries": 1, "assert_value": True  }, 
            { "client": "e1", "server": "e3", "port": 9951, "proto": "tcp", "retries": 1, "assert_value": True  }, 
            { "client": "e1", "server": "e3", "port": 9952, "proto": "tcp", "retries": 1, "assert_value": True  }, 
            { "client": "e1", "server": "e2", "port": 9950, "proto": "tcp", "retries": 1, "assert_value": True  }, 
            { "client": "e1", "server": "e2", "port": 9951, "proto": "tcp", "retries": 1, "assert_value": True  }, 
            { "client": "e1", "server": "e2", "port": 9952, "proto": "tcp", "retries": 1, "assert_value": True  }, 
            { "client": "e1", "server": "e3", "port": 9950, "proto": "udp", "retries": 1, "assert_value": True  }, 
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

    # Rule 6
    def test_rule_6(self):
        rules = [
            { "client": "client1", "server":"e1", "port": 5001, "proto": "tcp", "assert_value": True  },
            { "client": "client1", "server":"e2", "port": 5002, "proto": "tcp", "assert_value": True  },
            { "client": "client1", "server":"e3", "port": 5003, "proto": "tcp", "assert_value": True  },
            { "client": "client1", "server":"e1", "port": 6001, "proto": "udp", "assert_value": True  },
            { "client": "client1", "server":"e2", "port": 6002, "proto": "udp", "assert_value": True  },
            { "client": "client1", "server":"e3", "port": 6003, "proto": "udp", "assert_value": True  },
            { "client": "w1",      "server":"e1", "port": 7001, "proto": "tcp", "assert_value": True  },
            { "client": "w2",      "server":"e2", "port": 7002, "proto": "udp", "assert_value": True  },
            { "client": "w3",      "server":"e3", "port": 7003, "proto": "tcp", "assert_value": True  },
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))


    # Rule 7
    def test_rule_7(self):
        rules = [
            { "client": "e1", "server": "server3", "port": 500,  "proto": "udp", "assert_value": True  },
            { "client": "w1", "server": "server3", "port": 500,  "proto": "udp", "assert_value": True  },
            { "client": "e1", "server": "server3", "port": 1701, "proto": "udp", "assert_value": True  },
            { "client": "w1", "server": "server3", "port": 1701, "proto": "udp", "assert_value": True  },
            { "client": "e1", "server": "server1", "port": 500,  "proto": "udp", "assert_value": True  },
            { "client": "e1", "server": "server1", "port": 1701, "proto": "udp", "assert_value": True  },
        ]
        for rule in rules:
            check = self.check_helper(rule)
            if check != rule.get("assert_value"):
                print("\nFailed: {}".format(rule))
            self.assertEqual(check, rule.get("assert_value"))

if __name__ == '__main__':
    unittest.main()