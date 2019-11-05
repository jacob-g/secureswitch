from mininet.net import Mininet
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI
from mininet.node import RemoteController
from p4_mininet import P4Switch, P4Host
from time import sleep

class NetworkSetupTopo(Topo):
	def __init__(self, *args, **kwargs):
		Topo.__init__(self, *args, **kwargs)
		
		self.p4_network = {}
		
		for i in range(0, 2):
			self.p4_network[self.addSwitch(cls = P4Switch)] = []
		
		self.internet_switches = []
		for i in range(0, 5):
			self.internet_switches.append(self.addSwitch("s%d".format(i)))
			
topo = NetworkSetupTopo()
net = Mininet(topo = topo, host = P4Host, controller = None)
net.start()
sleep(5)
net.stop()