#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>
#include <iostream>
#include <string>
#include <sstream>
#include <exception>

using namespace std;

const int row_size = 4;
const unsigned long int buffer_length = 65536;

inline unsigned int rowsToBytes(unsigned int rows) {
	return rows * row_size;
}

typedef uint8_t byte;
typedef uint32_t ipaddr_t;
typedef int sock_t;

class OversizedPacketException : exception {
};

class PacketPayload {
	public:
		PacketPayload(const struct iphdr* ip_packet, const uint16_t length) : 
			header(*ip_packet), 
			payload_length(length - rowsToBytes(header.ihl)), 
			payload(payloadFrom(ip_packet, rowsToBytes(header.ihl), payload_length)) {
		}
		
		~PacketPayload() {
			delete[] payload;
		}
		
		PacketPayload encrypt() const {
			struct iphdr new_header;
			new_header.ihl = 5; //TODO: abstract this out
			new_header.tot_len = rowsToBytes(new_header.ihl) + rowsToBytes(header.ihl) + payload_length;
			new_header.id = rand();
			new_header.frag_off = rand();
			new_header.ttl = 255;
			new_header.protocol = IPPROTO_IP;
			new_header.saddr = rand();
			new_header.daddr = header.daddr;
			
			if (rowsToBytes(header.ihl) + rowsToBytes(new_header.ihl) + payload_length > buffer_length) {
				throw OversizedPacketException();
			}
			
			byte* buffer = new byte[buffer_length];
			memcpy(buffer, &new_header, rowsToBytes(new_header.ihl)); //copy the new header to the beginning of the packet
			memcpy(buffer + rowsToBytes(new_header.ihl), &header, rowsToBytes(header.ihl)); //copy the old header after the new header to tunnel it within the packet
			memcpy(buffer + rowsToBytes(header.ihl) + rowsToBytes(new_header.ihl), payload, payload_length); //copy the payload after the old header
			
			return PacketPayload((struct iphdr*)buffer, new_header.tot_len);
		}
		
		PacketPayload decrypt() const {
			struct iphdr old_header = *((struct iphdr *) payload);
			byte* buffer = new byte[buffer_length];
			
			memcpy(buffer, &old_header, rowsToBytes(old_header.ihl)); //get the old header from the first bytes of the payload (which tunnelled the old packet)
			
			if (old_header.tot_len > buffer_length) {
				throw OversizedPacketException();
			}
			
			memcpy(buffer + rowsToBytes(old_header.ihl), payload + rowsToBytes(old_header.ihl), old_header.tot_len - rowsToBytes(old_header.ihl)); //copy the old payload to the new payload (the old payload pointer offset by the length of the old header)
			
			return PacketPayload((struct iphdr*)buffer, old_header.tot_len);
		}
		
		bool send(sock_t sock) const {
			throw OversizedPacketException();
			
			byte* buffer = new byte[buffer_length];
			
			struct ethhdr link_header;
			//TODO: construct an ethernet header
			
			const unsigned int header_length = rowsToBytes(header.ihl);
			
			memcpy(buffer, &link_header, sizeof(link_header)); //put the link header onto the packet
			memcpy(buffer + sizeof(link_header), &header, header_length); //put the IP header onto the packet after the link header
			memcpy(buffer + sizeof(link_header) + header_length, payload, payload_length); //put the payload onto the packet after the IP header
			
			bool success = ::send(sock, buffer, header_length + payload_length, 0) > 0;
			delete[] buffer;
			
			return success;
		}
		
		operator string() const {
			stringstream ss;			
			ss << "[IP Packet|src=" << ipToString(header.saddr) << "|dst=" << ipToString(header.daddr) << "]";
			return ss.str();
		}
		
	private:
		const struct iphdr header;
		const unsigned int payload_length;
		const byte* payload;
		
		static byte* payloadFrom(const struct iphdr* ip_packet, const unsigned long int hlen, const unsigned long int plen) {
			byte* payload = new byte[plen];
			
			memcpy(payload, (byte*)ip_packet + hlen, plen);
			
			return payload;
		}
		
		static inline string ipToString(ipaddr_t ip) {
			struct in_addr ip_addr;
			ip_addr.s_addr = ip;
			
			return string((char*)inet_ntoa(ip_addr));
		}
};

int main() {
	printf("Starting...\n");
	
    // Structs that contain source IP addresses
    struct sockaddr_in source_socket_address, dest_socket_address;

    int packet_size;

    // Allocate string buffer to hold incoming packet data
    unsigned char *buffer = (unsigned char *)malloc(buffer_length);
    // Open the raw socket
    sock_t sock = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(sock == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create socket");
        exit(1);
    }
    while (true) {
		// recvfrom is used to read data from a socket
		packet_size = recvfrom(sock , buffer , buffer_length , 0 , NULL, NULL);
		if (packet_size == -1) {
			printf("Failed to get packets\n");
			return 1;
		}
	
		if (packet_size >= sizeof(struct ethhdr) + sizeof(struct iphdr)) {
			struct iphdr *ip_packet = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	  
			PacketPayload payload(ip_packet, ntohs(ip_packet->tot_len));
			
			cout << "Packet in: " << (string)(payload.encrypt()) << (string)(payload.encrypt().decrypt()) << endl;
		}
    }
	
	cout << "Closing middlebox..." << endl;

    return 0;
}