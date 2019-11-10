from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI

net = Mininet()

s0 = net.addSwitch('s0')
s1 = net.addSwitch('s1')

c0 = net.addController('c0', controller=RemoteController)

h0 = net.addHost('h0')
#h0.setIP('100.101.102.1', 24)

h1 = net.addHost('h1')
#h1.setIP('130.101.103.1', 24)

net.addLink(s0, s1)
net.addLink(h0, s0)
net.addLink(h1, s1)

net.start()
CLI(net)
net.stop()