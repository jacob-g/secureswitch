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

using namespace std;

typedef uint8_t byte;
typedef uint32_t ipaddr_t;
typedef int sock_t;

const unsigned long long int num_packets = 1000000;
const unsigned long long int payload_length = 10000;

int main() {
    sock_t send_sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (send_sock < 0) {
		perror("Failed to create packet sending socket");
		exit(1);
	}

    const byte* payload = new byte[payload_length];

    struct sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_port = htons(150);
    sin.sin_addr.s_addr = inet_addr("100.2.0.2");

    for (unsigned long long int counter = 0; counter < num_packets; counter++) {
        if (sendto(send_sock, payload, payload_length, 0, (struct sockaddr *)&sin, sizeof(struct sockaddr_in)) < 0) {
            cout << strerror(errno) << endl;
            exit(1);
        }
    }

    delete[] payload;
}
