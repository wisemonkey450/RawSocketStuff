/*
The purpose of this file is primarily to resolve IP addresses and contain helper
functions that are used to build IP packets for raw socket programming. Note that
we do not actually build the IP datagram here. We are merely defining helper 
functions that will be used to build the datagram. 

********************************************************************************

*/
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <libgen.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <netinet/ip.h>

#ifdef IP_BUILD_
#define IP_BUILD_

//This will return the source IP address
void ip_resolver(char*,struct ifaddrs*, char **);

//Checksum computation
/****************************************************************
*****************************************************************/
unsigned short calc_check_sum(unsigned short*, int);

//Checksum verification


//Build the IP header
int build_ip(struct ip**,/*Double pointer that will store our header
			 to return to the main function*/
	     int length,//length of the datagram
	     int frago,//fragment option
	     char* src,//Source IP address
	     char* dest,//Destination IP address
	     );
#endif //IP_BUILD_
