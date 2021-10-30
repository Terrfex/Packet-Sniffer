#include "packet_sniffer.h"

#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>

ErrorCode handle_packet(const uint8_t* pkt_buffer, uint16_t pkt_length)
{
	ErrorCode error_code = ERROR_SUCCESS;
	if (pkt_buffer == NULL)
	{
		error_code = ERROR_NULL;
		goto cleanup;
	}

	printf("first byte : %x, length: %u\n", pkt_buffer[0] , pkt_length);//prints the size of the packet

 cleanup:
	return error_code;
}

ErrorCode sniff_packets(const char* interface_name)
{
	ErrorCode error_code = ERROR_SUCCESS;
	ssize_t data_size;
	uint8_t packet_buffer[PACKET_BUFFER_SIZE] = { 0 };

	int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));//open sock
	if (raw_socket == -1)
	{
		perror("socket");
		error_code = ERROR_SOCKET;
		goto cleanup;
	}

	if(setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)) == -1)//setting the sock options and interface
	{
		perror("setsockopt");
		error_code = ERROR_SOCKET;
		goto cleanup;
	}

	while(1)//sniffing the packets
	{
		data_size = recvfrom(raw_socket, packet_buffer, PACKET_BUFFER_SIZE, 0, NULL, NULL);
		if (data_size == -1)//make sure we dint have an error
		{
			error_code = ERROR_RECV_FROM;
			perror("recvfrom");
			goto cleanup;
		}
		error_code = handle_packet(packet_buffer, data_size);
		if (error_code != ERROR_SUCCESS)
		{
			printf("Handle packt failed with: %d\n", error_code);
			goto cleanup;
		}
	}

cleanup://make sure we wont leak any resources
	if (raw_socket != -1 && close(raw_socket) == -1)
	{
		perror("close");
	}
	return error_code;
}
