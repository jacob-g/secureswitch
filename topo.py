from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI

net = Mininet()

s1 = net.addSwitch('s1', ip='100.0.0.0')
s2 = net.addSwitch('s2', ip='100.1.0.0')

c0 = net.addController('c0', controller=RemoteController)

h1enc = net.addHost('h1enc', ip="100.1.0.1")
h11 = net.addHost('h11', ip="100.1.0.2")

h2enc = net.addHost('h2enc', ip="100.2.0.1")
h21 = net.addHost('h21', ip="100.2.0.2")

net.addLink(s1, s2)
net.addLink(h1enc, s1)
net.addLink(h11, s1)
net.addLink(h2enc, s2)
net.addLink(h21, s2)

#disable responding to ping packets on h0
#TODO: figure out why h0 responds to "misrouted" ip packets
for encryptor in [h1enc, h2enc]:
	encryptor.cmd('echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all')
	encryptor.cmd('echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects') #don't send ICMP redirects

net.start()
CLI(net)
net.stop()