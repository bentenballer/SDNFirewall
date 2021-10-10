# from __future__ import division
import time


def check_connection(self, client, server, port, proto, assert_value, source_port=None, retries=0, debug=False, timeout=1):
    c = self.net.get(client)
    s = self.net.get(server)
    cip = c.IP()
    sip = s.IP()
    if debug:
        print("\nServer command: timeout -s2 {} nc -l {} {} {}".format(timeout + 1, "-u" if proto == "udp" else "", sip,
                                                                       port))
    s.sendCmd(' timeout -s2 {} nc -l {} {} {}'.format(timeout + 1, "-u" if proto == "udp" else "", sip, port))
    time.sleep(timeout)
    if debug:
        print("Client command: echo success | timeout {} nc -w {} {} {} {}".format(1 + timeout, timeout,
                                                                                   "-u" if proto == "udp" else "", sip,
                                                                                   port))
    cmon = c.cmd(
        ' echo success | timeout {} nc -w {} {} {} {} {}'.format(1 + timeout, timeout, "-u" if proto == "udp" else "", sip,
                                                              port, ("-p " + str(source_port)) if source_port else ""))
    smon = s.monitor()
    s.waiting = False
    time.sleep(timeout)
    if debug:
        print("Server output is: {}".format(smon))
        print("Client output is: {}".format(cmon))
    if 'success' in smon:
        return True
    elif retries > 0 and assert_value is not False:
        if debug:
            print("Retrying: check_connection({}, {}, {}, {}, {}, {}, {}, {})".format(client, server, port, proto,
                                                                                      assert_value, retries - 1, debug,
                                                                                      timeout * 1.5))
        return self.check_connection(client, server, port, proto, assert_value, retries - 1, debug, timeout * 1.5)
    else:
        return False


def check_gre(self, client, server, assert_value, retries=0, debug=False, timeout=1):
    c = self.net.get(client)
    s = self.net.get(server)
    cip = c.IP()
    sip = s.IP()

    # delete any existing GRE links
    smon = s.cmd('sudo ip link del gretest')
    cmon = c.cmd('sudo ip link del gretest')
    if debug: print("deleteing link")

    # create links - client endpoint 10.10.10.1 / server endpoint 11.11.11.2
    smon = s.cmd(f'ip tunnel add gretest mode gre remote {cip} local {sip} ttl 255')
    cmon = c.cmd(f'ip tunnel add gretest mode gre remote {sip} local {cip} ttl 255')
    if debug: print("adding new tunnel")

    smon = s.cmd('ip addr add 11.11.11.2 dev gretest')
    cmon = c.cmd('ip addr add 10.10.10.1 dev gretest')
    if debug: print("adding new address")

    smon = s.cmd('ifconfig gretest up')
    cmon = c.cmd('ifconfig gretest up')
    if debug: print("bring gre link up")

    # add routes
    smon = s.cmd('ip route add 10.10.10.0/24 via 11.11.11.2')
    cmon = c.cmd('ip route add 11.11.11.0/24 via 10.10.10.1')
    if debug: print("adding route tp iconfig")

    # ping to test connectivity through GRE Tunnel
    if debug:
        print("\nClient command: ping -c2 -i{} -w{} 11.11.11.2".format(round(timeout / 3, 2), timeout))
    cmon = c.cmd(' ping -c2 -i{} -w{} 11.11.11.2'.format(round(timeout / 3, 2), timeout))
    if debug:
        print("Client output is: {}".format(cmon))
    if '1 received' in cmon or '2 received' in cmon:
        return True
    elif retries > 0 and assert_value is not False:
        if debug:
            print(
                "Retrying: check_gre({}, {}, {}, {}, {}, {})".format(client, server, assert_value, retries - 1, debug,
                                                                     timeout * 1.5))
        return self.check_gre(client, server, assert_value, retries - 1, debug, timeout * 1.5)
    else:
        return False


def check_helper(self, rule):
    if rule.get("proto") == "tcp" or rule.get("proto") == "udp":
        return self.check_connection(**rule)
    elif rule.get("proto") == 'icmp':
        rule.pop("proto")
        return self.check_icmp(**rule)
    elif rule.get("proto") == 'gre':
        rule.pop("proto")
        return self.check_gre(**rule)
    else:
        print("Protocol \"{}\" not implemented.".format(rule.get("proto")))
        return False


def check_icmp(self, client, server, assert_value, retries=0, debug=False, timeout=1):
    c = self.net.get(client)
    s = self.net.get(server)
    sip = s.IP()
    if debug:
        print("\nClient command: ping -c2 -i{} -w{} {}".format(round(timeout / 3, 2), timeout, sip))
    cmon = c.cmd(' ping -c2 -i{} -w{} {}'.format(round(timeout / 3, 2), timeout, sip))
    if debug:
        print("Client output is: {}".format(cmon))
    if '1 received' in cmon or '2 received' in cmon:
        return True
    elif retries > 0 and assert_value is not False:
        if debug:
            print(
                "Retrying: check_icmp({}, {}, {}, {}, {}, {})".format(client, server, assert_value, retries - 1, debug,
                                                                      timeout * 1.5))
        return self.check_icmp(client, server, assert_value, retries - 1, debug, timeout * 1.5)
    else:
        return False
