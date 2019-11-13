#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<netinet/ip.h>
#include<sys/socket.h>
#include<arpa/inet.h>

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
			byte* cursor = ((byte*)ip_packet + hlen);
			
			for (unsigned long int offset = 0; offset < plen; offset++) {
				payload[offset] = *cursor;
				cursor++;
			}
			
			return payload;
		}
		
		static bool canMakePacket(const struct iphdr* ip_packet, const unsigned long int packet_size) {
			return packet_size > rowsToBytes(ip_packet->ihl);
		}
		
		unsigned short int port() {
			return ntohs(*((unsigned short int *)(payload + 2)));
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
    int sock = socket (AF_INET, SOCK_RAW, IPPROTO_TCP);
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
	
	  if (packet_size >= sizeof(struct iphdr)) {
		  struct iphdr *ip_packet = (struct iphdr *)buffer;
	  
		  if (PacketPayload::canMakePacket(ip_packet, packet_size)) {
				PacketPayload payload(ip_packet, packet_size);
				printf("Port: %d\n", payload.port());
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