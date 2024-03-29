from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI

class Endnet:
	hosts = []

	def __init__(self, net, number):
		self.switch = net.addSwitch("s%s" % number)
		
	def addHost(self, net, host):
		self.hosts.append(host)
		net.addLink(host.host, self.switch)
		
	def newHost(self, net, name, ip):
		host = Host(net, name, ip)
		self.addHost(net, host)
		return host
		
class Host:
	def __init__(self, net, name, ip):
		self.name = name
		self.host = net.addHost(name, ip=ip)
		
	def cmd(self, cmd):
		self.host.cmd(cmd)

net = Mininet()

#create a controller
c0 = net.addController('c0', controller=RemoteController)

#create each endnet
n1 = Endnet(net, 1)
n2 = Endnet(net, 2)
net.addLink(n1.switch, n2.switch)

#create each endnet's devices
h1enc = n1.newHost(net, 'h1enc', '100.1.0.1/8')
h11 = n1.newHost(net, 'h11', "100.1.0.2")
h12 = n1.newHost(net, 'h12', "100.1.0.3")
h13 = n1.newHost(net, 'h13', "100.1.0.4")
h14 = n1.newHost(net, 'h14', "100.1.0.5")

h2enc = n2.newHost(net, 'h2enc', "100.2.0.1/8")
h21 = n2.newHost(net, 'h21', "100.2.0.2")
h22 = n2.newHost(net, 'h22', "100.2.0.3")
h23 = n2.newHost(net, 'h23', "100.2.0.4")
h24 = n2.newHost(net, 'h24', "100.2.0.5")

#for each encryptor, disable any ICMP-related behavior and IP forwarding
for encryptor in [h1enc, h2enc]:
	encryptor.cmd('echo "1" > /proc/sys/net/ipv4/icmp_echo_ignore_all')
	encryptor.cmd('echo 0 | tee /proc/sys/net/ipv4/conf/*/send_redirects') #don't send ICMP redirects
	encryptor.cmd('echo "0" > /proc/sys/net/ipv4/ip_forward')

#start the middlebox program on each encryptor
h1enc.cmd('sudo middlebox/middlebox -a 47 -b 37 -f middlebox/pub_keys.txt &')
h2enc.cmd('sudo middlebox/middlebox -a 53 -b 67 -f middlebox/pub_keys.txt &')

net.start()
CLI(net)
net.stop()
