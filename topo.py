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
		
		s1 = self.addSwitch("s1", cls = P4Switch)
		
		h1 = self.addHost("h1")
		h2 = self.addHost("h2")
		
		self.addLink(h1, s1)
		self.addLink(h2, s1)
			
topo = NetworkSetupTopo()
net = Mininet(topo = topo, host = P4Host, controller = None)
net.start()
net.pingAll()
net.stop()