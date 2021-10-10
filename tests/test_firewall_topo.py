#!/usr/bin/python
# CS 6250 Spring 2021 - SDN Firewall Project with POX
# build leucosia-v20

# This file defines the default topology used to grade your assignment.  You
# may create additional firewall topologies by using this file as a template.
# All commands in here are standard Mininet commands like you have used in the first
# project.  This file has been updated to Python 3.

from mininet.topo import Topo
from mininet.net  import Mininet
from mininet.node import CPULimitedHost, RemoteController
from mininet.util import custom
from mininet.link import TCLink
from mininet.cli  import CLI


class FirewallTopo(Topo):
    '''
    This class defines the Mininet Topology for the network used in this project.  This network consists of
    the following hosts/networks:

    Headquarters Network (hq1-hq5).  Subnet 10.0.0.1/24
    US Network (us1-us5).  Subnet 10.0.1.0/24
    India Network (in1-in5).  Subnet 10.0.2.0/24
    China Network (cn1-cn5).  Subnet 10.0.3.0/24
    UK Network (uk1-uk5).  Subnet 10.0.4.0/24

    Refer to the host definitions below to get the IP Addresses and MAC Addresses
    '''

    def __init__(self, cpu=.1, bw=10, delay=None, **params):
        super(FirewallTopo, self).__init__()

        # Host in link configuration
        hconfig = {'cpu': cpu}
        lconfig = {'bw': bw, 'delay': delay}

        # Create the firewall switch
        s1 = self.addSwitch('s1')

        hq1 = self.addHost('hq1', ip='10.0.0.1', mac='00:00:00:00:00:1e', **hconfig)
        hq2 = self.addHost('hq2', ip='10.0.0.2', mac='00:00:00:00:01:1e', **hconfig)
        hq3 = self.addHost('hq3', ip='10.0.0.60', mac='00:00:00:00:02:1e', **hconfig)
        hq4 = self.addHost('hq4', ip='10.0.0.63', mac='00:00:00:00:03:1e', **hconfig)
        hq5 = self.addHost('hq5', ip='10.0.0.220', mac='00:00:00:00:04:1e', **hconfig)
        self.addLink(s1, hq1)
        self.addLink(s1, hq2)
        self.addLink(s1, hq3)
        self.addLink(s1, hq4)
        self.addLink(s1, hq5)

        us1 = self.addHost('us1', ip='10.0.1.1', mac='00:00:00:01:00:1e', **hconfig)
        us2 = self.addHost('us2', ip='10.0.1.2', mac='00:00:00:02:01:1e', **hconfig)
        us3 = self.addHost('us3', ip='10.0.1.33', mac='00:00:00:03:02:1e', **hconfig)
        us4 = self.addHost('us4', ip='10.0.1.34', mac='00:00:00:04:03:1e', **hconfig)
        us5 = self.addHost('us5', ip='10.0.1.125', mac='00:00:00:05:04:1e', **hconfig)
        self.addLink(s1, us1)
        self.addLink(s1, us2)
        self.addLink(s1, us3)
        self.addLink(s1, us4)
        self.addLink(s1, us5)

        in1 = self.addHost('in1', ip='10.0.2.1', mac='00:00:00:06:00:1e', **hconfig)
        in2 = self.addHost('in2', ip='10.0.2.2', mac='00:00:00:07:01:1e', **hconfig)
        in3 = self.addHost('in3', ip='10.0.2.3', mac='00:00:00:08:02:1e', **hconfig)
        in4 = self.addHost('in4', ip='10.0.2.126', mac='00:00:00:09:03:1e', **hconfig)
        in5 = self.addHost('in5', ip='10.0.2.125', mac='00:00:00:0a:04:1e', **hconfig)
        self.addLink(s1, in1)
        self.addLink(s1, in2)
        self.addLink(s1, in3)
        self.addLink(s1, in4)
        self.addLink(s1, in5)

        cn1 = self.addHost('cn1', ip='10.0.3.1', mac='00:00:00:0b:00:1e', **hconfig)
        cn2 = self.addHost('cn2', ip='10.0.3.2', mac='00:00:00:0c:01:1e', **hconfig)
        cn3 = self.addHost('cn3', ip='10.0.3.3', mac='00:00:00:0d:02:1e', **hconfig)
        cn4 = self.addHost('cn4', ip='10.0.3.4', mac='00:00:00:0e:03:1e', **hconfig)
        cn5 = self.addHost('cn5', ip='10.0.3.5', mac='00:00:00:0f:04:1e', **hconfig)
        self.addLink(s1, cn1)
        self.addLink(s1, cn2)
        self.addLink(s1, cn3)
        self.addLink(s1, cn4)
        self.addLink(s1, cn5)

        uk1 = self.addHost('uk1', ip='10.0.4.1', mac='00:00:00:10:00:1e', **hconfig)
        uk2 = self.addHost('uk2', ip='10.0.4.128', mac='00:00:00:11:01:1e', **hconfig)
        uk3 = self.addHost('uk3', ip='10.0.4.129', mac='00:00:00:02:02:1e', **hconfig)
        uk4 = self.addHost('uk4', ip='10.0.4.130', mac='00:00:00:03:03:1e', **hconfig)
        uk5 = self.addHost('uk5', ip='10.0.4.131', mac='00:00:00:14:04:1e', **hconfig)
        self.addLink(s1, uk1)
        self.addLink(s1, uk2)
        self.addLink(s1, uk3)
        self.addLink(s1, uk4)
        self.addLink(s1, uk5)

        wo1 = self.addHost('wo1', ip='10.254.0.254', mac='00:00:10:00:05:20', **hconfig)
        self.addLink(s1, wo1)


class OtherFWTopo(Topo):
    ''' Creates the following topoplogy:
                 e1   e2   e3
    server1  \     |    |    |
              \     \   |   /
    server2 ----  firewall (s1) --- client1
              /    /   |   \
    server3  /    |    |    |
                 w1    w2   w3
    '''

    def __init__(self, cpu=.1, bw=10, delay=None, **params):
        super(OtherFWTopo, self).__init__()

        # Host in link configuration
        hconfig = {'cpu': cpu}
        lconfig = {'bw': bw, 'delay': delay}

        # Create the firewall switch
        s1 = self.addSwitch('s1')

        # Create East hosts and links)
        e1 = self.addHost('e1', ip='10.0.0.1', mac='00:00:00:00:00:1e', **hconfig)
        e2 = self.addHost('e2', ip='10.0.0.2', mac='00:00:00:00:01:1e', **hconfig)
        e3 = self.addHost('e3', ip='10.0.0.60', mac='00:00:00:00:02:1e', **hconfig)
        self.addLink(s1, e1, port1=1, port2=1, **lconfig)
        self.addLink(s1, e2, port1=2, port2=1, **lconfig)
        self.addLink(s1, e3, port1=3, port2=1, **lconfig)

        # Create West hosts and links)
        w1 = self.addHost('w1', ip='10.0.1.1', mac='00:00:00:01:00:1e', **hconfig)
        w2 = self.addHost('w2', ip='10.0.1.2', mac='00:00:00:02:01:1e', **hconfig)
        w3 = self.addHost('w3', ip='10.0.1.33', mac='00:00:00:03:02:1e', **hconfig)
        self.addLink(s1, w1, port1=4, port2=1, **lconfig)
        self.addLink(s1, w2, port1=5, port2=1, **lconfig)
        self.addLink(s1, w3, port1=6, port2=1, **lconfig)

        # Add 'host1' for packet flood testing
        mobile1 = self.addHost('client1', ip='10.0.3.1', mac='00:00:00:0b:00:1e', **hconfig)
        self.addLink(s1, mobile1, port1=7, port2=1, **lconfig)

        # Create Server hosts and links)
        server1 = self.addHost('server1', ip='10.0.2.1', mac='00:00:00:06:00:1e', **hconfig)
        server2 = self.addHost('server2', ip='10.0.2.2', mac='00:00:00:07:01:1e', **hconfig)
        server3 = self.addHost('server3', ip='10.0.2.3', mac='00:00:00:08:02:1e', **hconfig)
        self.addLink(s1, server1, port1=8, port2=1, **lconfig)
        self.addLink(s1, server2, port1=9, port2=1, **lconfig)
        self.addLink(s1, server3, port1=10, port2=1, **lconfig)

def main():
    print("Starting Mininet Topology...")
    print("If you see a Unable to Contact Remote Controller, you have an error in your code...")
    print("Remember that you always use the Server IP Address when calling test scripts...")
    topo = OtherFWTopo()
    net = Mininet(topo=topo, link=TCLink, controller=RemoteController("OtherFWTopo",port=6633))

    net.start()
    CLI(net)

if __name__ == '__main__':
    main()