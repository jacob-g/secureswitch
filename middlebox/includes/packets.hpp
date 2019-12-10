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
			byte buffer[buffer_length];

			const unsigned int header_length = rowsToBytes(header.ihl);

			memcpy(buffer, &header, header_length);
			memcpy(buffer + header_length, payload, payload_length);

			return sock.send_to(header.daddr, buffer, ntohs(header.tot_len));
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

	typedef uint32_t encryption_type;

	/**
	* Encrypt this payload with a given public key
	*/
	EncryptablePacketPayload encrypt(const PublicEncryptionKey<encryption_type>& key) const {
		//create a new IP header with a bunch of random junk, with only the length (IHL/tot_len) and destination fields being correct
		const uint64_t tot_len = rowsToBytes(default_ihl) + (rowsToBytes(header.ihl) + payload_length) * size_multiplier;

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

		byte buffer[buffer_length];
		memcpy(buffer, &new_header, rowsToBytes(new_header.ihl)); //copy the new header to the beginning of the packet

		encryption_type* dst_cursor = (encryption_type*)(buffer + rowsToBytes(new_header.ihl));

		//TODO: join these foreach loops
		//copy and encrypt the header (the encrypted version may use different unit sizes for each source bytes, but since dst_cursor is of type encryption_type, that is already taken care of)
		for (byte* src = (byte*)&header; src < (byte*)&header + rowsToBytes(header.ihl); src++) {
			*dst_cursor = key.encrypt(*src);
			dst_cursor++;
		}

		//also copy and encrypt the payload
		for (byte* src = const_cast<byte*>(payload); src < payload + payload_length; src++) {
			*dst_cursor = key.encrypt(*src);
			dst_cursor++;
		}

		EncryptablePacketPayload encrypted((struct iphdr*)buffer, ntohs(new_header.tot_len));

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
private:
	const static unsigned int size_multiplier = sizeof(encryption_type);
};

#define PACKETS_INC
#endif // PACKETS_INC