#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<net/ethernet.h>

const int row_size = 4;
const unsigned long int buffer_length = 65536;

unsigned int rowsToBytes(unsigned int rows) {
	return rows * row_size;
}

typedef unsigned long int ipv4_addr;
typedef unsigned char byte;

class PacketPayload {
	public:
		PacketPayload(const struct iphdr* ip_packet, const unsigned long int length) : source(ip_packet->saddr), dest(ip_packet->daddr), header_length(rowsToBytes(ip_packet->ihl)), payload_length(length - header_length), payload(payloadFrom(ip_packet, header_length, payload_length)) {
		}
		
		~PacketPayload() {
			delete[] payload;
		}
		
		static byte* payloadFrom(const struct iphdr* ip_packet, const unsigned long int hlen, const unsigned long int plen) {
			byte* payload = new byte[plen];
			
			memcpy(payload, (byte*)ip_packet + hlen, plen);
			
			return payload;
		}
		
		static bool canMakePacket(const struct iphdr* ip_packet, const unsigned long int packet_size) {
			return packet_size > rowsToBytes(ip_packet->ihl);
		}
		
		PacketPayload encrypt() {
			//TODO: return another object with all metadata intact but the payload encrypted
			//byte* payload = new byte[payload_length];
			return *this;
		}
		
		bool send(int sock) {
			byte* buffer = new byte[65536];
			struct iphdr ip_packet;
			
			ip_packet.ihl = 5;
			ip_packet.version = 4;
			ip_packet.tos = 0;
			ip_packet.id = htons(rand());
			ip_packet.tot_len = ip_packet.ihl + payload_length;
			ip_packet.frag_off = 0;
			ip_packet.ttl = 255;
			ip_packet.protocol = IPPROTO_IP;
			ip_packet.check = 0;
			ip_packet.saddr = dest;
			ip_packet.daddr = dest;
			
			
			//TODO: calculate IP checksum
			//ip_packet.check = csum((unsigned short *) &ip_packet, ip_packet->tot_len);
			
			memcpy(buffer, &ip_packet, rowsToBytes(ip_packet.ihl));
			memcpy(buffer + rowsToBytes(ip_packet.ihl), payload, payload_length);
			
			bool success = ::send(sock, buffer, header_length + payload_length, 0) > 0;
			delete[] buffer;
			
			return success;
		}
		
	private:
		const unsigned int header_length;
		const unsigned int payload_length;
		const byte* payload;
		const ipv4_addr source, dest;
		
};

int main() {
	printf("Starting...\n");
	
    // Structs that contain source IP addresses
    struct sockaddr_in source_socket_address, dest_socket_address;

    int packet_size;

    // Allocate string buffer to hold incoming packet data
    unsigned char *buffer = (unsigned char *)malloc(buffer_length);
    // Open the raw socket
    int sock = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(sock == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create socket");
        exit(1);
    }
    while(1) {
      // recvfrom is used to read data from a socket
      packet_size = recvfrom(sock , buffer , buffer_length , 0 , NULL, NULL);
      if (packet_size == -1) {
        printf("Failed to get packets\n");
        return 1;
      }
	
	  if (packet_size >= sizeof(struct ethhdr) + sizeof(struct iphdr)) {
		  struct iphdr *ip_packet = (struct iphdr *)(buffer + sizeof(struct ethhdr));
	  
		  if (PacketPayload::canMakePacket(ip_packet, packet_size)) {
				PacketPayload payload(ip_packet, packet_size);
				//TODO: encrypt this
		  }

		  memset(&source_socket_address, 0, sizeof(source_socket_address));
		  source_socket_address.sin_addr.s_addr = ip_packet->saddr;
		  memset(&dest_socket_address, 0, sizeof(dest_socket_address));
		  dest_socket_address.sin_addr.s_addr = ip_packet->daddr;

		  printf("Incoming Packet: \n");
		  printf("Packet Size (bytes): %d\n",ntohs(ip_packet->tot_len));
		  printf("Source Address: %s\n", (char *)inet_ntoa(source_socket_address.sin_addr));
		  printf("Destination Address: %s\n", (char *)inet_ntoa(dest_socket_address.sin_addr));
		  printf("Identification: %d\n\n", ntohs(ip_packet->id));
		  
	  }
    }

    return 0;
}