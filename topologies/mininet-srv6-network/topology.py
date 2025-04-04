#!/usr/bin/python

from mininet.net import Mininet
from mininet.node import Node, OVSKernelSwitch, Controller, OVSController
from mininet.topo import Topo
from mininet.cli import CLI
from mininet.log import setLogLevel, info

class LinuxRouter(Node):
    "A Node with IP forwarding and SRv6 enabled."
    def config(self, **params):
        super(LinuxRouter, self).config(**params)
        # Enable IPv6 forwarding and SRv6 support
        self.cmd('sysctl -w net.ipv6.conf.all.forwarding=1')
        self.cmd('sysctl -w net.ipv6.conf.all.seg6_enabled=1')

    def terminate(self):
        self.cmd('sysctl -w net.ipv6.conf.all.forwarding=0')
        super(LinuxRouter, self).terminate()

class SRv6Topo(Topo):
    "Topology: two hosts and three routers in a linear chain."

    def build(self, **_opts):
        # Add hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        # Add routers (LinuxRouter nodes)
        r1 = self.addNode('r1', cls=LinuxRouter)
        r2 = self.addNode('r2', cls=LinuxRouter)
        r3 = self.addNode('r3', cls=LinuxRouter)

        # Create links:
        # Connect h1 to r1
        self.addLink(h1, r1, intfName2='r1-eth0')
        # Connect r1 to r2
        self.addLink(r1, r2, intfName1='r1-eth1', intfName2='r2-eth0')
        # Connect r2 to r3
        self.addLink(r2, r3, intfName1='r2-eth1', intfName2='r3-eth0')
        # Connect r3 to h2
        self.addLink(r3, h2, intfName1='r3-eth1')

def run():
    "Start the network and configure IPv6 addresses, routes and SRv6."
    topo = SRv6Topo()
    net = Mininet(topo=topo, controller=None)
    net.start()

    # Configure h1
    h1 = net.get('h1')
    h1.cmd("ip -6 addr add 2001:db8:1::1/64 dev h1-eth0")
    h1.cmd("ip -6 link set h1-eth0 up")
    h1.cmd("ip -6 route add default via 2001:db8:1::2")

    # Configure h2
    h2 = net.get('h2')
    h2.cmd("ip -6 addr add 2001:db8:3::2/64 dev h2-eth0")
    h2.cmd("ip -6 link set h2-eth0 up")
    h2.cmd("ip -6 route add default via 2001:db8:3::1")

    # Configure r1 (interface to h1 and r2)
    r1 = net.get('r1')
    r1.cmd("ip -6 addr add 2001:db8:1::2/64 dev r1-eth0")
    r1.cmd("ip -6 addr add 2001:db8:12::1/64 dev r1-eth1")
    r1.cmd("ip -6 link set r1-eth0 up")
    r1.cmd("ip -6 link set r1-eth1 up")

    # Configure r2 (interface to r1 and r3)
    r2 = net.get('r2')
    r2.cmd("ip -6 addr add 2001:db8:12::2/64 dev r2-eth0")
    r2.cmd("ip -6 addr add 2001:db8:23::1/64 dev r2-eth1")
    r2.cmd("ip -6 link set r2-eth0 up")
    r2.cmd("ip -6 link set r2-eth1 up")

    # Configure r3 (interface to r2 and h2)
    r3 = net.get('r3')
    r3.cmd("ip -6 addr add 2001:db8:23::2/64 dev r3-eth0")
    r3.cmd("ip -6 addr add 2001:db8:3::1/64 dev r3-eth1")
    r3.cmd("ip -6 link set r3-eth0 up")
    r3.cmd("ip -6 link set r3-eth1 up")

    # Set basic routing (for fallback and reachability)
    # r1: route to h2's network via r2
    r1.cmd("ip -6 route add 2001:db8:3::/64 via 2001:db8:12::2")
    # r2: routes to h1 and h2's networks
    r2.cmd("ip -6 route add 2001:db8:1::/64 via 2001:db8:12::1")
    r2.cmd("ip -6 route add 2001:db8:3::/64 via 2001:db8:23::2")
    # r3: route to h1's network via r2
    r3.cmd("ip -6 route add 2001:db8:1::/64 via 2001:db8:23::1")

    # --- SRv6 Configuration ---
    # On r1, add an SRv6 route for packets destined to h2's subnet.
    # This route encapsulates packets with an SRv6 header carrying the segment list: first hop is r3's h2-facing address,
    # then the final endpoint at h2.
    r1.cmd("ip -6 route add 2001:db8:3::/64 encap seg6 mode encap segs 2001:db8:23::2,2001:db8:3::1 dev r1-eth1")

    info("SRv6 topology running. Use the Mininet CLI to test connectivity.\n")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run()

