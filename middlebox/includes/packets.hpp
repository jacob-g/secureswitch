#include <exception>
#include <sstream>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <string.h>
#include "sockets.hpp"

#ifndef PACKETS_INC

/**
* An exception thrown when a packet is beyond the storable size
*/
class OversizedPacketException : std::exception {
};

const int row_size = 4;
extern const unsigned long int buffer_length = 65536;
const uint8_t default_ihl = 5;

/**
* Convert rows in an IP packet to bytes
*/
inline unsigned int rowsToBytes(unsigned int rows) {
	return rows * row_size;
}

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

		/**
		* Send this packet on a given socket
		*/
		bool send(RawIPSocket& sock) const {
			const uint16_t packet_length = ntohs(header.tot_len);

			byte buffer[packet_length];

			const unsigned int header_length = rowsToBytes(header.ihl);

			memcpy(buffer, &header, header_length);
			memcpy(buffer + header_length, payload, payload_length);

			return sock.send_to(header.daddr, buffer, packet_length);
		}

		operator std::string() const {
			std::stringstream ss;
			ss << "[IP Packet|src=" << ipToString(header.saddr) << "|dst=" << ipToString(header.daddr) << "]";
			return ss.str();
		}

	protected:
		const struct iphdr header;
		const unsigned int payload_length;
		const byte* payload;

		static inline byte* payloadFrom(const struct iphdr* ip_packet, const unsigned long int hlen, const unsigned long int plen) {
			byte* payload = new byte[plen];

			memcpy(payload, ((byte*)ip_packet) + hlen, plen);

			return payload;
		}

		static inline std::string ipToString(ipaddr_t ip) {
			struct in_addr ip_addr;
			ip_addr.s_addr = ip;

			return std::string((char*)inet_ntoa(ip_addr));
		}
};

class EncryptablePacketPayload : public PacketPayload {
public:
	EncryptablePacketPayload(const struct iphdr* ip_packet, const uint16_t length) : PacketPayload(ip_packet, length) {};

	typedef byte decryption_type;
	typedef uint32_t encryption_type;

	/**
	* Encrypt this payload with a given public key
	*/
	EncryptablePacketPayload encrypt(const PublicEncryptionKey<decryption_type, encryption_type>& key) const {
		//create a new IP header with a bunch of random junk, with only the length (IHL/tot_len) and destination fields being correct
		const uint64_t tot_len = rowsToBytes(default_ihl) + (rowsToBytes(header.ihl) + payload_length) * sizeof(encryption_type) / sizeof(decryption_type);

		struct iphdr new_header;
		new_header.ihl = default_ihl;
		new_header.tot_len = htons((uint16_t)tot_len);
		new_header.saddr = rand();
		new_header.daddr = header.daddr;
		new_header.version = 4;
		new_header.protocol = 0;

		//ensure that the packet isn't too big
		if (tot_len > buffer_length) {
			throw OversizedPacketException();
		}

		//put the origin all in one contiguous block of memory
		byte origin[rowsToBytes(header.ihl) + payload_length];
		memcpy(origin, &header, rowsToBytes(header.ihl));
		memcpy(origin + rowsToBytes(header.ihl), payload, payload_length);

		//make a buffer where the destination will reside
		byte buffer[tot_len];
		memcpy(buffer, &new_header, rowsToBytes(new_header.ihl)); //copy the new header to the beginning of the packet

		encryption_type* dst_cursor = (encryption_type*)(buffer + rowsToBytes(new_header.ihl));

		//copy and encrypt the header (the encrypted version may use different unit sizes for each source bytes, but since dst_cursor is of type encryption_type, that is already taken care of)
		for (decryption_type* src = origin; src < (decryption_type*)(origin + rowsToBytes(header.ihl) + payload_length); src++) {
			*dst_cursor = key.encrypt(*src);
			dst_cursor++;
		}

		return EncryptablePacketPayload((struct iphdr*)buffer, ntohs(new_header.tot_len));
	}

	PacketPayload decrypt(const PrivateEncryptionKey<decryption_type, encryption_type> key) const {
		byte buffer[buffer_length];

		//copy the encrypted packet to the buffer that will represent the unencrypted packet
		//the source is of the encryption type, which may be a different length than a single byte, but the pointer operations take care of that
		decryption_type* dst = (decryption_type*)buffer;
		for (encryption_type* src = (encryption_type*)payload; (byte*)src < payload + payload_length; src++) {
			*dst = key.decrypt(*src);
			dst++;
		}

		struct iphdr old_header = *((struct iphdr *) buffer);

		return PacketPayload((struct iphdr*)buffer, ntohs(old_header.tot_len));
	}
};

#define PACKETS_INC
#endif // PACKETS_INC
