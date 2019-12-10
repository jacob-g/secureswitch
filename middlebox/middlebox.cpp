#include "includes/types.hpp"
#include "includes/rsa.hpp"
#include "includes/packets.hpp"
#include "includes/sockets.hpp"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <iostream>
#include <string>
#include <sstream>
#include <exception>
#include <set>
#include <map>
#include <tuple>
#include <fstream>

using namespace std;

const byte encrypted_source_last_eth_byte = 3;
const byte unencrypted_source_last_eth_byte = 4;

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
