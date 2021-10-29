#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdint.h>


#define PACKET_BUFFER_SIZE 65536//max buffer size

int main(int argc, char * argv[])
{
	int error_code = 0;
	ssize_t data_size;
	uint8_t packet_buffer[PACKET_BUFFER_SIZE];

	if (argc != 2)//make sure we got the required params(interface name is needed)
	{
		printf("Usage: %s [IFNAME]\n", argv[0]);
		error_code = 1;
		goto cleanup;
	}
	const char* interface_name = argv[1];

	int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));//open sock
	if (raw_socket == -1)
	{
		perror("socket");
		error_code = 2;
		goto cleanup;
	}

	if(setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, interface_name, strlen(interface_name)) == -1)//setting the sock options and interface
	{
		perror("setsockopt");
		error_code = 2;
		goto cleanup;
	}

	while(1)//sniffing the packets
	{
		data_size = recvfrom(raw_socket, packet_buffer, PACKET_BUFFER_SIZE, 0, NULL, NULL);
		if (data_size == -1)//make sure we dint have an error
		{
			error_code = 3;
			perror("recvfrom");
			goto cleanup;
		}
		//here we have a packet
		printf("%lu\n", data_size);//prints the size of the packet
	}

cleanup://make sure we wont leak any resources
	if (raw_socket != -1 && close(raw_socket) == -1)
	{
		perror("close");
	}
	return error_code;
}
