#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#ifndef TYPES_INC
typedef uint8_t byte; //a byte
typedef uint32_t ipaddr_t; //an IP address
typedef int sock_t; //a socket
#define TYPES_INC
#endif //TYPES_INC
