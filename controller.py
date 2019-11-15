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

class SecureSwitchController(app_manager.RyuApp):
	OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
	
	switch_local_mac = "00:00:00:00:01:01"
	switch_interchange_mac = "00:00:00:00:01:02"
	
	end_nets = {
		0: ["100.0.0.1", "100.0.0.2"],
		1: ["100.1.0.1", "100.1.0.2"]
	}
	device_macs = {}
	device_ports = {}

	def __init__(self, *args, **kwargs):
		super(SecureSwitchController, self).__init__(*args, **kwargs)
		
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		datapath = ev.msg.datapath
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		#find all attached devices to this switch
		for ip_list in self.end_nets.values():
			for ip in ip_list:
				self.send_arp_request(datapath, self.switch_local_mac, "0.0.0.0", ip)
						
		
		#say that for any unmatched packets, send them to the controller
		self.add_flow_entry(datapath, 0, parser.OFPMatch(), [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)], 0)
		return
		
	def send_arp_request(self, dp, src_mac, src_ip, dst_ip):
		self.send_arp_pkt(dp, arp.ARP_REQUEST, src_mac, src_ip, "FF:FF:FF:FF:FF:FF", dst_ip)
		return
		
	def send_arp_response(self, dp, port, src_mac, src_ip, dst_mac, dst_ip):
		self.send_arp_pkt(dp, arp.ARP_REPLY, src_mac, src_ip, dst_mac, dst_ip, port)
		return
	
	def send_arp_pkt(self, dp, opcode, src_mac, src_ip, dst_mac, dst_ip, port = -1):
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
				
		if eth.ethertype == ether_types.ETH_TYPE_ARP:
			pkt_arp = pkt.get_protocol(arp.arp)
			print pkt_arp
			
			if pkt_arp.opcode == arp.ARP_REQUEST:
				if mac_src != self.switch_local_mac:
					self.send_arp_response(dp, in_port, self.switch_local_mac, pkt_arp.dst_ip, eth.src, pkt_arp.src_ip)
				return
				
			elif pkt_arp.opcode == arp.ARP_REPLY: #we received an ARP response, so record the MAC and IP addresses
				self.device_macs[pkt_arp.src_ip] = pkt_arp.src_mac
				self.device_ports[pkt_arp.src_mac] = in_port
				return
		
		elif eth.ethertype == ether_types.ETH_TYPE_IP:
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
		
			# handle IP packets
			pkt_ip = pkt.get_protocol(ipv4.ipv4)
			print pkt_ip
			
			#get the IP packet data
			pkt_ip = pkt.get_protocol(ipv4.ipv4)
			ip_dst = pkt_ip.dst
			ip_src = pkt_ip.src
			
			if self.same_endnet(pkt_ip):
				#if the two devices are on the same network, just forward the packet normally
								
				data = None
				if msg.buffer_id == ofproto.OFP_NO_BUFFER:
					data = msg.data
					
				final_mac = self.device_macs[ip_dst]
					
				actions = [
					parser.OFPActionSetField(eth_dst=final_mac),
					parser.OFPActionOutput(self.device_ports[final_mac])
				]
				
				data = None
				if msg.buffer_id == ofproto.OFP_NO_BUFFER:
					data = msg.data
				
				dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data))
				
				#TODO: add a flow
				
			else:
				if self.in_endnet(pkt_ip):
					#handle packets that were sent through SecureSwitch
					if self.is_incoming(mac_dst, pkt_ip):															
						final_mac = self.device_macs[ip_dst]
						
						actions = [
							parser.OFPActionSetField(eth_dst=final_mac),
							parser.OFPActionOutput(self.device_ports[final_mac])
						]
						
						data = None
						if msg.buffer_id == ofproto.OFP_NO_BUFFER:
							data = msg.data
						
						dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=self.unwrapped_decrypted_ip_pkt(data)))
						
						return
					elif self.is_outgoing(mac_dst, pkt_ip):										
						actions = [
							parser.OFPActionSetField(eth_dst=self.switch_interchange_mac),
							parser.OFPActionOutput(ofproto.OFPP_FLOOD)
						]
						
						data = None
						if msg.buffer_id == ofproto.OFP_NO_BUFFER:
							data = msg.data
						
						dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=self.wrapped_encrypted_ip_pkt(ip_dst, data)))
						
						return
				
		#if we received a packet of unknown protocol, defensively drop it
		return
		
	def in_endnet(self, pkt_ip):
		return self.endnet_of(pkt_ip.src) != -1
				
	def same_endnet(self, pkt_ip):
		return self.endnet_of(pkt_ip.src) == self.endnet_of(pkt_ip.dst)
		
	def wrapped_encrypted_ip_pkt(self, dst_ip, data):
		pkt_eth = ethernet.ethernet(dst=self.switch_interchange_mac,
									src=self.switch_local_mac,
									ethertype=ether.ETH_TYPE_IP)
									
		pkt_ip = ipv4.ipv4(src='0.0.0.0', dst=dst_ip)
		
		wrapped_pkt = packet.Packet(data=self.encrypt(data))
		wrapped_pkt.add_protocol(pkt_eth)
		wrapped_pkt.add_protocol(pkt_ip)
		
		return wrapped_pkt
		
	def unwrapped_decrypted_ip_pkt(self, data):
		pkt = packet.Packet(data)
		
		#TODO: decrypt the packet
		
		return data
		
	def decrypt(self, data):
		return data
		
	def encrypt(self, data):
		return data
		
	def endnet_of(self, ip):
		for net_id, ips in self.end_nets.items():
			if ip in ips:
				return net_id
		
		raise -1
		
	def is_incoming(self, eth_dst, pkt_ip):
		return eth_dst == self.switch_interchange_mac
	
	def is_outgoing(self, eth_dst, pkt_ip):
		return eth_dst == self.switch_local_mac

	@set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
	def flow_removed_handler(self, ev):
		# handle FlowRemoved event	
		return
		# WRITE YOUR CODE HERE
		