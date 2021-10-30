#ifndef __PACKET_SNIFFER_H__
#define __PACKET_SNIFFER_H__

#include <stdint.h>

#define PACKET_BUFFER_SIZE 65536//max buffer size
#define MAX_IP_LEN 16


typedef enum
{
	ERROR_SUCCESS = 0,
	ERROR_BAD_ARGUMENTS,
	ERROR_SOCKET,
	ERROR_RECV_FROM,
	ERROR_NULL
} ErrorCode;

ErrorCode handle_packet(const uint8_t* pkt_buffer, uint16_t pkt_length);

ErrorCode sniff_packets(const char* interface_name);

#endif
