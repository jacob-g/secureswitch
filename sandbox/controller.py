from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.lib.mac import haddr_to_bin
import random
import json
from itertools import chain 

def keyFromValue(dict, value):
	for key, val in dict.items():
		if val == value:
			return key
	raise Exception("Value not present in dictionary")
	
def keyFromValueLists(dict, value):
	for key, val in dict.items():
		if value in val:
			return key
	raise Exception("Value not present in dictionary")

class LoadBalancer(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	mac_to_port = {}
	server_macs = {}
	client_macs = {}

	def __init__(self, *args, **kwargs):
		super(LoadBalancer, self).__init__(*args, **kwargs)
		
	#send an ARP response on a specific port
	def send_proxied_arp_response(self, dp, port, src_mac, src_ip, dst_mac, dst_ip):
		# relay arp response to clients or servers
		# no need to insert entries into the flow table
		self.send_proxied_arp_pkt(dp, arp.ARP_REPLY, src_mac, src_ip, dst_mac, dst_ip, port)
		return
		
	#send an ARP request on all ports
	def send_proxied_arp_request(self, dp, src_mac, src_ip, dst_ip):
		self.send_proxied_arp_pkt(dp, arp.ARP_REQUEST, src_mac, src_ip, "FF:FF:FF:FF:FF:FF", dst_ip)
		return
	
	#send a proxied ARP packet with given data, and leave port blank to flood
	def send_proxied_arp_pkt(self, dp, opcode, src_mac, src_ip, dst_mac, dst_ip, port = -1):
		eth_rsp = ethernet.ethernet(dst_mac, src_mac, ether.ETH_TYPE_ARP)
		arp_rsp = arp.arp(opcode=opcode, src_mac=src_mac, src_ip=src_ip, dst_mac=dst_mac, dst_ip=dst_ip)
		
		p = packet.Packet()
		p.add_protocol(eth_rsp)
		p.add_protocol(arp_rsp)
		p.serialize()
				
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		
		if port == -1:
			port = ofproto.OFPP_FLOOD
		
		dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=ofproto.OFP_NO_BUFFER, in_port=ofproto.OFPP_CONTROLLER, actions=[ parser.OFPActionOutput(port) ], data=p.data))
		return
		
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser

		#say that for any unmatched packets, send them to the controller
		self.add_flow_entry(datapath, 0, parser.OFPMatch(), [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)], 0)
		return
				 
	def add_flow_entry(self, datapath, priority, match, actions, timeout=10):
		# helper function to insert flow entries into flow table
		# by default, the idle_timeout is set to be 10 seconds
		parser = datapath.ofproto_parser
				
		datapath.send_msg(parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=[parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)], idle_timeout=timeout))
		return
	
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):
		#get all the packet metadata
		msg = ev.msg
		dp = msg.datapath
		dpid = dp.id
		
		#extract the ethernet metadata
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocol(ethernet.ethernet)
		mac_dst = eth.dst
		mac_src = eth.src
						
		in_port = msg.match['in_port']
		
		#store the mapping of this MAC address and datapath to the port so we know how to route traffic going forwards
		if mac_src not in self.mac_to_port:
			self.mac_to_port[mac_src] = {}
		self.mac_to_port[mac_src][dpid] = in_port
				
		if eth.ethertype == ether_types.ETH_TYPE_ARP:
			#handle ARP packets
			pkt_arp = pkt.get_protocol(arp.arp)
												
			if pkt_arp.opcode == arp.ARP_REQUEST: #we found an ARP request, so always respond with the service MAC address (whether for the server or client)
				self.send_proxied_arp_response(dp, in_port, "00:11:22:33:44:55", pkt_arp.dst_ip, mac_src, pkt_arp.src_ip)
				return
				
			#if it's an unrecognized ARP type, defensively drop the packet
			return
		
		elif eth.ethertype == ether_types.ETH_TYPE_IP:
			# handle IP packets
			
			#get the IP packet data
			pkt_ip = pkt.get_protocol(ipv4.ipv4)
			ip_dst = pkt_ip.dst
			ip_src = pkt_ip.src
			
			print pkt_ip
		else:
			print "Unrecognized IP packet"
		return

	@set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
	def flow_removed_handler(self, ev):
		# handle FlowRemoved event	
		return
		# WRITE YOUR CODE HERE
		