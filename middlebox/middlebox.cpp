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
#include <algorithm>

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

template<typename T>
T mod_inverse(T a, T m)
{
    T top_left = m;
	long long int top_right = 0;

	T bottom_left = a;
	long long int bottom_right = 1;

	while (bottom_left > 0) {
		T quotient = top_left / bottom_left;

		T old_bottom_left = bottom_left;
		bottom_left = top_left % bottom_left;
		top_left = old_bottom_left;

		long long int old_bottom_right = bottom_right;
		bottom_right = top_right - quotient * bottom_right;
		top_right = old_bottom_right;
	}

    return top_right < 0 ? top_right + m : top_right;
}


inline unsigned int rowsToBytes(unsigned int rows) {
	return rows * row_size;
}

typedef uint8_t byte;
typedef uint32_t ipaddr_t;
typedef int sock_t;

class OversizedPacketException : exception {
};

template<typename T>
T mod_exponent(T num, T exponent, T mod) {
	T working_power = num;
	for (T i = 0; i < exponent - 1; i++) {
		working_power = (working_power * num) % mod;
	}
	return working_power;
}

template<typename T>
class PublicEncryptionKey {
	public:
		const T pub_e, pub_n;

		PublicEncryptionKey(T in_e, T in_n) :
			pub_e(in_e),
			pub_n(in_n) {};

		T encrypt(byte unencrypted) const {
			return mod_exponent<T>(unencrypted, pub_e, pub_n);
		}
};

template<typename T>
class PrivateEncryptionKey {
	public:
		PrivateEncryptionKey(T in_p, T in_q) :
			priv_p(in_p),
			priv_q(in_q),
			totient((priv_p - 1) * (priv_q - 1)),
			pub_key(PublicEncryptionKey<T>(smallest_coprime(totient), in_p * in_q)),
			priv_d(mod_inverse(pub_key.pub_e, totient)) {}

		T decrypt(T encrypted) const {
			return mod_exponent<T>(encrypted, priv_d, pub_key.pub_n);
		}

	private:
		const T priv_p, priv_q, totient;

		static T smallest_coprime(T num) {
			T guess = 2;
			while (__gcd(guess, num) > 1) {
				guess++;
			}
			return guess;
		}

	public:
		const PublicEncryptionKey<T> pub_key;

	private:
		const T priv_d;
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

		typedef uint32_t encryption_type;

		PacketPayload encrypt(const PublicEncryptionKey<encryption_type>& key) const {
			struct iphdr new_header;
			new_header.ihl = 5; //TODO: abstract this out
			new_header.tot_len = rowsToBytes(new_header.ihl) + (rowsToBytes(header.ihl) + payload_length) * size_multiplier;
			new_header.saddr = rand();
			new_header.daddr = header.daddr;

			if (header.tot_len > buffer_length) {
				throw OversizedPacketException();
			}

			byte* buffer = new byte[buffer_length];
			memcpy(buffer, &new_header, rowsToBytes(new_header.ihl)); //copy the new header to the beginning of the packet

			encryption_type* dst_cursor = (encryption_type*)(buffer + rowsToBytes(new_header.ihl));

			//TODO: join these foreach loops
			//copy and encrypt the header (the encrypted version may use different unit sizes for each source bytes, but since dst_cursor is of type encryption_type, that is already taken care of)
			//FIXME: we're getting an off-by-one error where the cursor is overwriting something in the packet header!
			for (byte* src = (byte*)&header; src < (byte*)&header + rowsToBytes(header.ihl); src++) {
				//*dst_cursor = key.encrypt(*src);
				dst_cursor++;
			}

			//also copy and encrypt the payload
			encryption_type* encrypted_payload = dst_cursor;
			for (byte* src = const_cast<byte*>(payload); src < payload + payload_length; src++) {
				*dst_cursor = key.encrypt(*src);
				dst_cursor++;
			}

			return PacketPayload((struct iphdr*)buffer, new_header.tot_len);
		}

		PacketPayload decrypt(const PrivateEncryptionKey<encryption_type> key) const {
			byte* buffer = new byte[buffer_length];

			//copy the encrypted packet to the buffer that will represent the unencrypted packet
			//the source is of the encryption type, which may be a different length than a single byte, but the pointer operations take care of that
			byte* dst = buffer;
			for (encryption_type* src = (encryption_type*)payload; (byte*)src < payload + payload_length; src++) {
				*dst = key.decrypt(*src);
				dst++;
			}

			struct iphdr old_header = *((struct iphdr *) buffer);

			return PacketPayload((struct iphdr*)buffer, old_header.tot_len);
		}

		bool send(sock_t sock) const {
            struct sockaddr_in sin;
            sin.sin_family = AF_INET;
            sin.sin_port = htons (0);
            sin.sin_addr.s_addr = header.daddr;

            byte* buffer = new byte[buffer_length];

            const unsigned int header_length = rowsToBytes(header.ihl);
            cout << "Sending address: " << ipToString(header.saddr) << endl;
            cout << "Receiving address: " << ipToString(header.daddr) << endl;
            cout << "HLEN: " << header_length << endl;
            cout << "PLEN: " << payload_length << endl;

            memcpy(buffer, &header, header_length);
            memcpy(buffer + header_length, payload, payload_length);

            cout << "Total length: " << header.tot_len << endl;

            bool result = sendto(sock, buffer, header.tot_len, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0;
            delete[] buffer;

            return result;
		}

		operator string() const {
			stringstream ss;
			ss << "[IP Packet|src=" << ipToString(header.saddr) << "|dst=" << ipToString(header.daddr) << "]";
			return ss.str();
		}

	private:
		const static unsigned int size_multiplier = sizeof(encryption_type);
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
	cout << "Starting middlebox..." << endl;

	PrivateEncryptionKey<uint32_t> key(37, 19);

    int packet_size;

    // Allocate string buffer to hold incoming packet data
    unsigned char *buffer = (unsigned char *)malloc(buffer_length);
    // Open the raw socket
    sock_t sock = socket (AF_PACKET, SOCK_RAW, htons(ETH_P_IP));
    if(sock < 0) {
        //socket creation failed, may be because of non-root privileges
        perror("Failed to create listening socket");
        exit(1);
    }

	sock_t send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (send_sock < 0) {
		perror("Failed to create packet sending socket");
		exit(1);
	}
	const int on = 1;
	setsockopt (send_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on));

    byte* packet = new byte[buffer_length];
	struct iphdr* pkt_ip = (struct iphdr*)packet;
	pkt_ip->ihl = 5;
	pkt_ip->tot_len = 356;
	pkt_ip->saddr = inet_addr("100.1.2.2");
	pkt_ip->daddr = inet_addr("100.1.2.3");
	packet[20] = rand();
	packet[21] = rand();
	packet[22] = rand();
	packet[23] = rand();
	PacketPayload(pkt_ip, pkt_ip->tot_len).send(send_sock);

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
				PacketPayload encrypted = payload.encrypt(key.pub_key);
				cout << " -> Sending: " << (string)encrypted << endl;
				encrypted.send(send_sock);
				cout << " -> Decrypted: " << (string)(encrypted.decrypt(key)) << endl;
			} catch (OversizedPacketException) {
				//drop the packet
				cerr << "Packet dropped due to being too large" << endl;
			}
		}
    }

	cout << "Closing middlebox..." << endl;

    return 0;
}
