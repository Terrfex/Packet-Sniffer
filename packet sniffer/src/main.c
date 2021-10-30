#include "packet_sniffer.h"

#include <stdio.h>


int main(int argc, char * argv[])
{
	ErrorCode error_code = ERROR_SUCCESS;

	if (argc != 2)//make sure we got the required params
	{
		printf("Usage: %s [IFNAME]\n", argv[0]);
		error_code = ERROR_BAD_ARGUMENTS;
		goto cleanup;
	}
	const char* interface_name = argv[1];

	error_code = sniff_packets(interface_name);

cleanup:
	return error_code;
}
