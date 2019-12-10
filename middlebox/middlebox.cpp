#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <iostream>
#include <string>
#include <sstream>
#include <exception>
#include <algorithm>
#include <set>
#include <map>
#include <tuple>
#include <fstream>

using namespace std;

const int row_size = 4;
const unsigned long int buffer_length = 65536;

/**
* Calculate the mod inverse of a number given a modulus
*/
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

/**
* Convert rows in an IP packet to bytes
*/
inline unsigned int rowsToBytes(unsigned int rows) {
	return rows * row_size;
}

typedef uint8_t byte; //a byte
typedef uint32_t ipaddr_t; //an IP address
typedef int sock_t; //a socket

const byte encrypted_source_last_eth_byte = 3;
const byte unencrypted_source_last_eth_byte = 4;

class OversizedPacketException : exception {
};

/**
* Perform a exponent mod some number by use of successive squares
*/
template<typename T>
T mod_exponent(T num, T exponent, T mod) {
	T working_exponent = exponent;
	T working_power = num;
	T result = 1;
	while (working_exponent > 0) {
		if (working_exponent % 2 == 1) {
			result = (result * working_power) % mod;
		}

		working_power = (working_power * working_power) % mod;
		working_exponent >>= 1;
	}
	return result;
}

/**
* A public encryption key
*/
template<typename T>
class PublicEncryptionKey {
	public:
		const T pub_e, pub_n;

		PublicEncryptionKey(T in_e, T in_n) :
			pub_e(in_e),
			pub_n(in_n) {};

		PublicEncryptionKey() : PublicEncryptionKey(0, 0) {};

		PublicEncryptionKey(const PublicEncryptionKey& other) : PublicEncryptionKey(other.pub_e, other.pub_n) {};

        /**
        * Encrypt a byte with this public key
        */
		T encrypt(byte unencrypted) const {
			return mod_exponent<T>(unencrypted, pub_e, pub_n);
		}

		PublicEncryptionKey operator=(const PublicEncryptionKey& other) {
			return PublicEncryptionKey(other.pub_e, other.pub_n);
		}
};

/**
* A private encryption key
*/
template<typename T>
class PrivateEncryptionKey {
	public:
		PrivateEncryptionKey(T in_p, T in_q) :
			priv_p(in_p),
			priv_q(in_q),
			totient((priv_p - 1) * (priv_q - 1)),
			pub_key(PublicEncryptionKey<T>(smallest_coprime(totient), in_p * in_q)),
			priv_d(mod_inverse(pub_key.pub_e, totient)) {}

        /**
        * Unencrypt an encrypted bit sequence with this private key
        */
		T decrypt(T encrypted) const {
			return mod_exponent<T>(encrypted, priv_d, pub_key.pub_n);
		}

	private:
		const T priv_p, priv_q, totient;

        /**
        * Return the smallest number coprime with a given number
        */
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

class RawSocket {
public:
    RawSocket(sock_t i_sock_id): sock_id(i_sock_id) {
        if (i_sock_id < 0) {
            cerr << "Failed to create socket" << endl;
            exit(1);
        }
    };

    int receive_any(byte* buffer, const int buffer_length) {
        int length = recvfrom(sock_id , buffer , buffer_length , 0 , NULL, NULL);
        if (length < 0) {
            cerr << "Failed to receive from socket" << endl;
            exit(1);
        }
        return length;
    }

    bool send_to(const ipaddr_t ip, byte* buffer, const int length) {
        struct sockaddr_in sin;
        sin.sin_family = AF_INET;
        sin.sin_port = htons (0);
        sin.sin_addr.s_addr = ip;

        return sendto(sock_id, buffer, length, 0, (struct sockaddr *) &sin, sizeof (sin)) < 0;
    }
protected:
    const sock_t sock_id;
};

class RawDataLinkSocket : public RawSocket {
public:
    RawDataLinkSocket() : RawSocket(socket(AF_PACKET, SOCK_RAW, htons(ETH_P_IP))) {};
};

class RawIPSocket : public RawSocket {
public:
    RawIPSocket() : RawSocket(socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) {
        const int on = 1;
        setsockopt (sock_id, IPPROTO_IP, IP_HDRINCL, &on, sizeof (on));
    }
};

/**
* Represents a packet payload
*/
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

        /**
        * Encrypt this payload with a given public key
        */
		PacketPayload encrypt(const PublicEncryptionKey<encryption_type>& key) const {
			struct iphdr new_header;
			new_header.ihl = 5; //TODO: abstract this out
			new_header.tot_len = htons(rowsToBytes(new_header.ihl) + (rowsToBytes(header.ihl) + payload_length) * size_multiplier);
			new_header.saddr = rand();
			new_header.daddr = header.daddr;
			new_header.version = 4;
			new_header.protocol = 0;

			if (ntohs(new_header.tot_len) > buffer_length) {
				throw OversizedPacketException();
			}

			byte buffer[buffer_length];
			memcpy(buffer, &new_header, rowsToBytes(new_header.ihl)); //copy the new header to the beginning of the packet

			encryption_type* dst_cursor = (encryption_type*)(buffer + rowsToBytes(new_header.ihl));

			//TODO: join these foreach loops
			//copy and encrypt the header (the encrypted version may use different unit sizes for each source bytes, but since dst_cursor is of type encryption_type, that is already taken care of)
			int counter = 0;
			for (byte* src = (byte*)&header; src < (byte*)&header + rowsToBytes(header.ihl); src++) {
				*dst_cursor = key.encrypt(*src);
				dst_cursor++;
				counter++;
			}

			//also copy and encrypt the payload
			for (byte* src = const_cast<byte*>(payload); src < payload + payload_length; src++) {
				*dst_cursor = key.encrypt(*src);
				dst_cursor++;
				counter++;
			}

			PacketPayload encrypted((struct iphdr*)buffer, ntohs(new_header.tot_len));

			return encrypted;
		}

		PacketPayload decrypt(const PrivateEncryptionKey<encryption_type> key) const {
			byte buffer[buffer_length];

			//copy the encrypted packet to the buffer that will represent the unencrypted packet
			//the source is of the encryption type, which may be a different length than a single byte, but the pointer operations take care of that
			byte* dst = buffer;
			for (encryption_type* src = (encryption_type*)payload; (byte*)src < payload + payload_length; src++) {
				*dst = key.decrypt(*src);
				dst++;
			}

			struct iphdr old_header = *((struct iphdr *) buffer);

			PacketPayload decrypted((struct iphdr*)buffer, ntohs(old_header.tot_len));

			return decrypted;
		}

        /**
        * Send this packet on a given socket
        */
		bool send(RawIPSocket& sock) const {
			byte buffer[buffer_length];

			const unsigned int header_length = rowsToBytes(header.ihl);

			memcpy(buffer, &header, header_length);
			memcpy(buffer + header_length, payload, payload_length);

            return sock.send_to(header.daddr, buffer, ntohs(header.tot_len));
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

			memcpy(payload, ((byte*)ip_packet) + hlen, plen);

			return payload;
		}

		static inline string ipToString(ipaddr_t ip) {
			struct in_addr ip_addr;
			ip_addr.s_addr = ip;

			return string((char*)inet_ntoa(ip_addr));
		}
};

const string arg_str = "a:b:f:";

template<typename T>
tuple<PrivateEncryptionKey<T>, string> cmdLineArgs(int argc, char** argv) {
	T prime_a = 0, prime_b = 0;
	string filename;
	int c;
	while ((c = getopt(argc, argv, arg_str.c_str())) != -1) {
		switch (c) {
			case 'a':
				prime_a = atoi(optarg);
				break;
			case 'b':
				prime_b = atoi(optarg);
				break;
			case 'f':
				filename = optarg;
				break;
			default:
				cerr << "Unknown command line argument: " << (char)c << endl;
				break;
		}
	}

	if (prime_a == 0 || prime_b == 0) {
		cerr << "Missing private key, specify with -a and -b" << endl;
		exit(1);
	}

	if (filename.size() == 0) {
		cerr << "Missing public key filename, specify with -f" << endl;
		exit(1);
	}

	return make_tuple(PrivateEncryptionKey<T>(prime_a, prime_b), filename);
}

template<typename T>
map<ipaddr_t, PublicEncryptionKey<T> > pubKeysFromFile(const string fileName) {
	map<ipaddr_t, PublicEncryptionKey<T> > result;

	ifstream file(fileName);
	string ip_str;
	T e, n;
	while (file >> ip_str, file >> e, file >> n) {
		PublicEncryptionKey<T> key(e, n);
		ipaddr_t ip = inet_addr(ip_str.c_str());
		result.insert(typename map<ipaddr_t, PublicEncryptionKey<T> >::value_type(ip, key));
	}
	file.close();

	return result;
}

int main(int argc, char* argv[]) {
	tuple<PrivateEncryptionKey<PacketPayload::encryption_type>, string> cmd_args = cmdLineArgs<PacketPayload::encryption_type>(argc, argv);

	map<ipaddr_t, PublicEncryptionKey<PacketPayload::encryption_type> > pub_keys = pubKeysFromFile<PacketPayload::encryption_type>(get<1>(cmd_args));

	cout << "Starting middlebox..." << endl;

	PrivateEncryptionKey<PacketPayload::encryption_type> priv_key = get<0>(cmd_args);

	byte buffer[buffer_length];

	int packet_size;

	// Allocate string buffer to hold incoming packet data
	//unsigned char *buffer = (unsigned char *)malloc(buffer_length);
	// Open the raw socket
	RawDataLinkSocket in_sock = RawDataLinkSocket();
    RawIPSocket out_sock = RawIPSocket();


	while (true) {
		// recvfrom is used to read data from a socket
		packet_size = in_sock.receive_any(buffer, buffer_length);

		if (packet_size >= sizeof(struct ethhdr) + sizeof(struct iphdr)) {
			struct ethhdr* eth_header = (struct ethhdr*)buffer;
			const byte last_eth_src_byte = eth_header->h_source[5];

			struct iphdr *ip_packet = (struct iphdr *)(buffer + sizeof(struct ethhdr));

			try {
				PacketPayload payload(ip_packet, packet_size - - sizeof(struct ethhdr) - rowsToBytes(ip_packet->ihl));

				switch (last_eth_src_byte) {
					case unencrypted_source_last_eth_byte:
						{
							//encrypt he packet if we have a registered public key for the destination (and if not, drop it)
							PublicEncryptionKey<PacketPayload::encryption_type> pub_key = pub_keys[ip_packet->daddr];
							if (pub_key.pub_n > 0) {
								PacketPayload encrypted = payload.encrypt(pub_key);
								encrypted.send(out_sock);
							}
						}
						break;
					case encrypted_source_last_eth_byte:
						{
							PacketPayload decrypted = payload.decrypt(priv_key);
							decrypted.send(out_sock);
						}
						break;
					default:
						break;
				}


			} catch (OversizedPacketException) {
				//drop the packet
				cerr << "Packet dropped due to being too large" << endl;
			}
		}
	}

	cout << "Closing middlebox..." << endl;

	return 0;
}
