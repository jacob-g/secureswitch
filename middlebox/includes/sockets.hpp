#include <iostream>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include "types.hpp"

#ifndef SOCKETS_INC
class RawSocket {
public:
	RawSocket(sock_t i_sock_id): sock_id(i_sock_id) {
		if (i_sock_id < 0) {
			std::cerr << "Failed to create socket" << std::endl;
			exit(1);
		}
	};

	int receive_any(byte* buffer, const int buffer_length) {
		return recvfrom(sock_id , buffer , buffer_length , 0 , NULL, NULL);
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
#define SOCKETS_INC
#endif // SOCKETS_INC
