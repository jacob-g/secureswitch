from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI

net = Mininet()

s0 = net.addSwitch('s0', ip='100.0.0.0')
s1 = net.addSwitch('s1', ip='100.1.0.0')

c0 = net.addController('c0', controller=RemoteController)

h0 = net.addHost('h0', ip="100.0.0.1")
h1 = net.addHost('h1', ip="100.0.0.2")

h2 = net.addHost('h2', ip="100.1.0.1")
h3 = net.addHost('h3', ip="100.1.0.2")

net.addLink(s0, s1)
net.addLink(h0, s0)
net.addLink(h1, s0)
net.addLink(h2, s1)
net.addLink(h3, s1)

#disable responding to ping packets on h0
#TODO: figure out why h0 responds to "misrouted" ip packets
h0.cmd('echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all')
h0.cmd('echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects') #don't send ICMP redirects

net.start()
CLI(net)
net.stop()