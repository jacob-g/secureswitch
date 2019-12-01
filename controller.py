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
	switch_encrypted_mac = "00:00:00:00:01:03"
	switch_unencrypted_mac = "00:00:00:00:01:04"
	
	unknown_endnet_value = 0
	
	end_nets = {
		1: ["100.1.0.1", "100.1.0.2"],
		2: ["100.2.0.1", "100.2.0.2"]
	}
	end_net_encryption_devices = {
		1: "100.1.0.1",
		2: "100.2.0.1"
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
		
		self.add_default_flow_entry(datapath, self.unknown_endnet_value)
		
		#find all attached devices to this switch
		for ip_list in self.end_nets.values():
			for ip in ip_list:
				self.send_arp_request(datapath, self.switch_local_mac, "0.0.0.0", ip)
		
		return
		
	def add_default_flow_entry(self, datapath, cookie):
		ofproto = datapath.ofproto
		parser = datapath.ofproto_parser
		
		self.add_flow_entry(datapath, 0, parser.OFPMatch(), [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)], 0, cookie)
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
				 
	def add_flow_entry(self, datapath, priority, match, actions, timeout=10, cookie=0):
		# helper function to insert flow entries into flow table
		# by default, the idle_timeout is set to be 10 seconds
		parser = datapath.ofproto_parser
				
		datapath.send_msg(parser.OFPFlowMod(datapath=datapath, priority=priority, match=match, instructions=[parser.OFPInstructionActions(datapath.ofproto.OFPIT_APPLY_ACTIONS, actions)], idle_timeout=timeout, cookie=cookie))
		return
		
	@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
	def packet_in_handler(self, ev):	
		#get all the packet metadata
		msg = ev.msg
		dp = msg.datapath
		dpid = dp.id
								
		pkt = packet.Packet(msg.data)
		eth = pkt.get_protocol(ethernet.ethernet)
		mac_dst = eth.dst
		mac_src = eth.src
										
		in_port = msg.match['in_port']
		
		switch_endnet = msg.cookie
				
		if eth.ethertype == ether_types.ETH_TYPE_ARP:
			pkt_arp = pkt.get_protocol(arp.arp)
			
			self.device_macs[pkt_arp.src_ip] = mac_src
			self.device_ports[pkt_arp.src_mac] = in_port
			
			if pkt_arp.opcode == arp.ARP_REQUEST:
				if pkt_arp.src_ip in self.end_net_encryption_devices.values():
					print "Received ARP request for encryptor:", pkt_arp
					if self.endnet_of(pkt_arp.dst_ip) == switch_endnet:
						self.send_arp_response(dp, in_port, self.switch_local_mac, pkt_arp.dst_ip, eth.src, pkt_arp.src_ip)
					else:
						self.send_arp_response(dp, in_port, self.switch_encrypted_mac, pkt_arp.dst_ip, eth.src, pkt_arp.src_ip)
				elif mac_src != self.switch_local_mac:
					print "Received ARP request from local device:", pkt_arp
					self.send_arp_response(dp, in_port, self.switch_local_mac, pkt_arp.dst_ip, eth.src, pkt_arp.src_ip)
				return
				
			elif pkt_arp.opcode == arp.ARP_REPLY: #we received an ARP response, so record the MAC and IP addresses
				print "Received ARP response:", pkt_arp
				if switch_endnet == self.unknown_endnet_value:
					print "Setting endnet"
					self.add_default_flow_entry(dp, self.endnet_of(pkt_arp.src_ip))
				return
		
		elif eth.ethertype == ether_types.ETH_TYPE_IP:
			ofproto = dp.ofproto
			parser = dp.ofproto_parser
		
			# handle IP packets
			pkt_ip = pkt.get_protocol(ipv4.ipv4)
			
			#get the IP packet data
			pkt_ip = pkt.get_protocol(ipv4.ipv4)
			ip_dst = pkt_ip.dst
			ip_src = pkt_ip.src
						
			if self.same_endnet(pkt_ip):
				#if the two devices are on the same network, just forward the packet normally
				
				print "Received local packet", pkt_ip
				
				data = None
				if msg.buffer_id == ofproto.OFP_NO_BUFFER:
					data = msg.data
					
				final_mac = self.device_macs[ip_dst]
									
				actions = [
					parser.OFPActionSetField(eth_src=self.switch_local_mac),
					parser.OFPActionSetField(eth_dst=final_mac),
					parser.OFPActionOutput(self.device_ports[final_mac])
				]
				
				data = None
				if msg.buffer_id == ofproto.OFP_NO_BUFFER:
					data = msg.data
				
				dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data))
				
				#TODO: add a flow
				return
				
			else:
				if self.in_endnet(ip_dst):
					#handle packets that were sent through SecureSwitch
					if self.is_incoming_encrypted(switch_endnet, mac_dst, pkt_ip):
						#an encrypted packet is inbound, forward it to the encryptor
						print "Inbound encrypted packet on endnet", switch_endnet, pkt_ip
						
						encryptor_ip = self.end_net_encryption_devices[switch_endnet]
						encryptor_mac = self.device_macs[encryptor_ip]
						encryptor_port = self.device_ports[encryptor_mac]
						
						self.send_with_flow(dp, msg, in_port, mac_src, mac_dst, encryptor_port, self.switch_encrypted_mac, encryptor_mac)
						
						return
						
					elif self.is_incoming_decrypted(switch_endnet, mac_src, mac_dst, pkt_ip):
						print "Inbound decrypted packet on endnet", switch_endnet, pkt_ip
							
						final_mac = self.device_macs[ip_dst]
						
						self.send_with_flow(dp, msg, in_port, mac_src, mac_dst, self.device_ports[final_mac], self.switch_local_mac, final_mac)
						
						return
						
					elif self.is_outgoing_unencrypted(mac_dst, pkt_ip):
						#the packet is outgoing, send it to the encryption device
						encryptor_ip = self.end_net_encryption_devices[switch_endnet]
						encryptor_mac = self.device_macs[encryptor_ip]
						encryptor_port = self.device_ports[encryptor_mac]
						
						print "Outbound unencrypted on endnet", switch_endnet, " from:", pkt_ip.src, "to", pkt_ip.dst, "encrypting with", encryptor_ip, "on port", encryptor_port
						
						self.send_with_flow(dp, msg, in_port, mac_src, mac_dst, encryptor_port, self.switch_unencrypted_mac, encryptor_mac)
												
						return
						
					elif self.is_outgoing_encrypted(mac_dst, pkt_ip) and self.endnet_of(ip_src) == -1:
						print "Outbound encrypted on endnet", switch_endnet, " from:", pkt_ip.src, "to:", pkt_ip.dst
						print " -> src:", mac_src, "dst:", mac_dst
						
						self.send_with_flow(dp, msg, in_port, mac_src, mac_dst, 1, self.switch_local_mac, self.switch_interchange_mac)
						
						return
						
					else:
						print "Dropped IP packet on endnet", switch_endnet, ":", pkt_ip, eth
						
						self.add_flow_entry(dp, 1, parser.OFPMatch(eth_type=0x800, in_port=in_port, ipv4_src=ip_src, eth_src=mac_src, eth_dst=mac_dst), [])
						
						return
				else:
					print "Dropped IP packet not in endnet", pkt_ip
				
		#if we received a packet of unknown protocol, defensively drop it
		return
		
	def send_with_flow(self, dp, msg, in_port, orig_eth_src, orig_eth_dst, out_port, new_eth_src, new_eth_dst):
		ofproto = dp.ofproto
		parser = dp.ofproto_parser
		
		actions = [
			parser.OFPActionSetField(eth_dst=new_eth_dst),
			parser.OFPActionSetField(eth_src=new_eth_src),
			parser.OFPActionOutput(out_port)
		]
		
		data = None
		if msg.buffer_id == ofproto.OFP_NO_BUFFER:
			data = msg.data
		
		dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data))
		
		self.add_flow_entry(dp, 1, parser.OFPMatch(eth_type=0x800, in_port=in_port, eth_src=orig_eth_src, eth_dst=orig_eth_dst), actions)
		
		return
				
	def in_endnet(self, ip_addr):
		return self.endnet_of(ip_addr) != -1
				
	def same_endnet(self, pkt_ip):
		return self.endnet_of(pkt_ip.src) == self.endnet_of(pkt_ip.dst)
		
	def endnet_of(self, ip):
		for net_id, ips in self.end_nets.items():
			if ip in ips:
				return net_id
		
		return -1
		
	def is_incoming_encrypted(self, endnet, eth_dst, pkt_ip):
		return eth_dst == self.switch_interchange_mac and self.endnet_of(pkt_ip.dst) == endnet
		
	def is_incoming_decrypted(self, endnet, mac_src, eth_dst, pkt_ip):
		return self.endnet_of(pkt_ip.dst) == endnet and mac_src == self.device_macs[self.end_net_encryption_devices[endnet]] and eth_dst == self.switch_local_mac
	
	def is_outgoing_unencrypted(self, eth_dst, pkt_ip):
		return eth_dst == self.switch_local_mac
		
	def is_outgoing_encrypted(self, eth_dst, pkt_ip):
		return eth_dst == self.switch_encrypted_mac

	@set_ev_cls(ofp_event.EventOFPFlowRemoved, MAIN_DISPATCHER)
	def flow_removed_handler(self, ev):
		return
		