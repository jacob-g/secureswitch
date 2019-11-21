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
	
	end_nets = {
		0: ["100.0.0.1", "100.0.0.2"],
		1: ["100.1.0.1", "100.1.0.2"]
	}
	end_net_encryption_devices = {
		0: "100.0.0.1",
		1: "100.1.0.1"
	}
	device_macs = {}
	device_ports = {}

	def __init__(self, *args, **kwargs):
	
		super(SecureSwitchController, self).__init__(*args, **kwargs)
		
	@set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
	def switch_features_handler(self, ev):
		#FIXME: this fails for the first time this is run
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
			
			if pkt_arp.opcode == arp.ARP_REQUEST:
				if pkt_arp.src_ip in self.end_net_encryption_devices.values():
					print "Received ARP request for encryptor:", pkt_arp
					self.send_arp_response(dp, in_port, self.switch_encrypted_mac, pkt_arp.dst_ip, eth.src, pkt_arp.src_ip)
				elif mac_src != self.switch_local_mac:
					print "Received ARP request from local device:", pkt_arp
					self.send_arp_response(dp, in_port, self.switch_local_mac, pkt_arp.dst_ip, eth.src, pkt_arp.src_ip)
				return
				
			elif pkt_arp.opcode == arp.ARP_REPLY: #we received an ARP response, so record the MAC and IP addresses
				print "Received ARP response:", pkt_arp
				self.device_macs[pkt_arp.src_ip] = pkt_arp.src_mac
				self.device_ports[pkt_arp.src_mac] = in_port
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
				
			else:
				if self.in_endnet(pkt_ip):
					print "Originates in endnet"
					#handle packets that were sent through SecureSwitch
					if self.is_incoming(mac_dst, pkt_ip):	
						#the packet is incoming to our network
						print "Local packet", pkt_ip
						
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
						print "Outbound packet on port ", in_port
						if mac_src == self.device_macs[self.end_net_encryption_devices[0]]:
							#TODO: better detect IP packets sent from the encryptor
							print "Received encrypted packet pretending to be from ", pkt_ip.src, " actually to ", pkt_ip.dst
							return
						elif mac_dst == self.switch_local_mac:
							#the packet is outgoing, send it to the encryption device
							encryptor_ip = self.end_net_encryption_devices[self.endnet_of(pkt_ip.src)]
							encryptor_mac = self.device_macs[encryptor_ip]
							encryptor_port = self.device_ports[encryptor_mac]
							
							print "Encrypting with", encryptor_ip, "on port", encryptor_port
							
							actions = [
								parser.OFPActionSetField(eth_src=self.switch_encrypted_mac),
								parser.OFPActionSetField(eth_dst=encryptor_mac),
								parser.OFPActionOutput(encryptor_port)
							]
							
							data = None
							if msg.buffer_id == ofproto.OFP_NO_BUFFER:
								data = msg.data
							
							#TODO: figure out why h1 knows anything!
							dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id, in_port=in_port, actions=actions, data=data))
							
							return
						else:
							print "Dropped outbound packet"
							#defensively drop any outbound packets not sent to a correct MAC address
							return
				
		#if we received a packet of unknown protocol, defensively drop it
		return
		
	def in_endnet(self, pkt_ip):
		return self.endnet_of(pkt_ip.src) != -1
				
	def same_endnet(self, pkt_ip):
		return self.endnet_of(pkt_ip.src) == self.endnet_of(pkt_ip.dst)
		
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
		return
		