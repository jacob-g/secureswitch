#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <iostream>
#include <string>
#include <sstream>
#include <exception>

using namespace std;

const int row_size = 4;
const unsigned long int buffer_length = 65536;

//checksum from https://www.binarytides.com/raw-sockets-c-code-linux/
unsigned short csum(unsigned short *ptr,int nbytes) 
{
	register long sum;
	unsigned short oddbyte;
	register short answer;

	sum=0;
	while(nbytes>1) {
		sum+=*ptr++;
		nbytes-=2;
	}
	if(nbytes==1) {
		oddbyte=0;
		*((u_char*)&oddbyte)=*(u_char*)ptr;
		sum+=oddbyte;
	}

	sum = (sum >> 16)+(sum & 0xffff);
	sum = sum + (sum >> 16);
	answer=(short)~sum;
	
	return(answer);
}


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
			memcpy(buffer + rowsToBytes(new_header.ihl) + rowsToBytes(header.ihl), payload, payload_length); //copy the payload after the old header
			
			//TODO: factor encryption logic out into its own function to separate it from tunneling logic
			for (byte* cursor = buffer + rowsToBytes(new_header.ihl); cursor < buffer + rowsToBytes(new_header.ihl) + new_header.tot_len; cursor++) {
				*cursor = ~*cursor;
			}
			
			
			struct iphdr* in_situ_header = (struct iphdr*)buffer;
			in_situ_header->check = csum((unsigned short *)buffer, new_header.tot_len);
			
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
			
			for (byte* cursor = buffer; cursor < buffer + old_header.tot_len; cursor++) {
				*cursor = ~*cursor;
			}
			
			return PacketPayload((struct iphdr*)buffer, old_header.tot_len);
		}
		
		bool send(sock_t sock) const {
			byte* buffer = new byte[buffer_length];
			
			const unsigned int header_length = rowsToBytes(header.ihl);
			
			memcpy(buffer, &header, header_length); //put the IP header onto the packet after the link header
			memcpy(buffer + header_length, payload, payload_length); //put the payload onto the packet after the IP header
			
			sockaddr_in sin = {0};
			
			//this IS sending out ARP requests and getting replies successfully!
			bool success = ::sendto(sock, buffer, header_length + payload_length, 0, (struct sockaddr *)&sin, sizeof(sin)) > 0;
			if (!success) {
				cerr << "Error " << errno << ": " << strerror(errno) << endl;
			}
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
	
    int packet_size;

    // Allocate string buffer to hold incoming packet data
    unsigned char *buffer = (unsigned char *)malloc(buffer_length);
    // Open the raw socket
    sock_t sock = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(sock == -1)
    {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create listening socket");
        exit(1);
    }
	
	sock_t send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (send_sock < 0) {
		cerr << "Failed to create sending socket" << endl;
		exit(1);
	}
	const int on = 1;
	setsockopt (send_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on));
	
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
			
			try {
				cout << "Received packet: " << (string)payload << endl;
				PacketPayload encrypted = payload.encrypt();
				cout << " -> Sending: " << (string)encrypted << endl;
				cout << " -> Decrypted" << (string)(encrypted.decrypt()) << endl;
				encrypted.send(send_sock);
			} catch (OversizedPacketException) {
				//drop the packet
				cerr << "Packet dropped due to being too large" << endl;
			}
		}
    }
	
	cout << "Closing middlebox..." << endl;

    return 0;
}