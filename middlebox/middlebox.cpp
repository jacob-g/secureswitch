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

/**
* Read out useful metadata the command line arguments
*/
template<typename T>
tuple<PrivateEncryptionKey<T>, string> cmdLineArgs(int argc, char** argv) {
    const string arg_str = "a:b:f:";

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

/**
* Read the public keys in a file
*/
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

typedef enum{ENCRYPTED, UNENCRYPTED, UNKNOWN} encryption_state;

/**
* Find out whether a packet is encrypted or unencrypted based on the metadata in the ethernet header
*/
encryption_state encryption_state_of(ethhdr* eth_header) {
    const byte encrypted_source_last_eth_byte = 3;
    const byte unencrypted_source_last_eth_byte = 4;

    const byte last_eth_src_byte = eth_header->h_source[5];

    switch (last_eth_src_byte) {
    case unencrypted_source_last_eth_byte:
        return UNENCRYPTED;
    case encrypted_source_last_eth_byte:
        return ENCRYPTED;
    default:
        return UNKNOWN;
    }
}

int main(int argc, char* argv[]) {
	tuple<PrivateEncryptionKey<EncryptablePacketPayload::encryption_type>, string> cmd_args = cmdLineArgs<EncryptablePacketPayload::encryption_type>(argc, argv); //read the command line arguments

	map<ipaddr_t, PublicEncryptionKey<EncryptablePacketPayload::encryption_type> > pub_keys = pubKeysFromFile<EncryptablePacketPayload::encryption_type>(get<1>(cmd_args)); //read the public key file given in the command line args

	PrivateEncryptionKey<EncryptablePacketPayload::encryption_type> priv_key = get<0>(cmd_args); //get the private key from the command line arguments

    cout << "Starting middlebox..." << endl;

	byte buffer[buffer_length];

	int packet_size;

	// open the sockets
	RawDataLinkSocket in_sock = RawDataLinkSocket();
    RawIPSocket out_sock = RawIPSocket();


	while (true) {
		// recvfrom is used to read data from a socket
		packet_size = in_sock.receive_any(buffer, buffer_length);

		if (packet_size >= sizeof(struct ethhdr) + sizeof(struct iphdr)) { //make sure that the packet at least has an ethernet and IP header
			struct ethhdr* eth_header = (struct ethhdr*)buffer; //extract the ethernet header
			struct iphdr *ip_packet = (struct iphdr *)(buffer + sizeof(struct ethhdr)); //extract the IP header after the ethernet header

			try {
				EncryptablePacketPayload payload(ip_packet, packet_size - - sizeof(struct ethhdr) - rowsToBytes(ip_packet->ihl)); //convert the packet into a usable type

				switch (encryption_state_of(eth_header)) {
					case UNENCRYPTED:
						{
							//encrypt he packet if we have a registered public key for the destination (and if not, drop it)
							PublicEncryptionKey<EncryptablePacketPayload::encryption_type> pub_key = pub_keys[ip_packet->daddr];
							if (pub_key) {
								EncryptablePacketPayload encrypted = payload.encrypt(pub_key);
								encrypted.send(out_sock);
							}
						}
						break;
					case ENCRYPTED:
						{
						    //decrypt an encrypted packet
							PacketPayload decrypted = payload.decrypt(priv_key);
							decrypted.send(out_sock);
						}
						break;
					default:
					    //drop unknown packets
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
