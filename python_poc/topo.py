from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI

net = Mininet()

s0 = net.addSwitch('s0')
s1 = net.addSwitch('s1')

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

net.start()
CLI(net)
net.stop()