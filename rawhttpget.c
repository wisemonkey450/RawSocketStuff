/*
Standard includes
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

/*
Raw socket struct support
*/

#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <sys/time.h>
/*
Header declarations for custom functions
*/

#include "url_parse.h"
#include "ip_build.h"
#include "tcp_build.h"
#include "struct_def.h"
/*
Color support defines
*/

#define RED   "\x1B[31m"
#define GRN   "\x1B[32m"
#define YEL   "\x1B[33m"
#define BLU   "\x1B[34m"
#define MAG   "\x1B[35m"
#define CYN   "\x1B[36m"
#define WHT   "\x1B[37m"
#define RESET "\x1B[0m"

#define ETHER_TYPE 0x0800

void hexdump(unsigned char *buffer, unsigned long index) {
  unsigned long i;
  printf("hexdump on address %p:\n", buffer);
  for (i=0;i<index;i++)
  {
    printf("%02x ",buffer[i]);
  }
  printf("\n");
}

void usage(){
	printf(RED"[!] Error!\n");
	printf(RED"[!]"GRN" You must supply an argument: USAGE: ./rawhttpget [URL]\n"RESET);
	exit(-1);
}

void error(char **msg){
	printf(RED"[!] Error!\n"RESET);
	//printf(RED"[!] "YEL "%s\n"RESET,*msg);
	printf(YEL "[!]");
	printf("%s",*msg);
	printf("\n"RESET);
	exit(-1);
}

int main(int argc, char **argv){

	if(argc < 2){
		usage();
	}
	
	//Grab the base url name using basename (see libgen.h)
	//Create the file path for openning the file later
	char *url = argv[1];
	char *file_name = (char*)malloc(20*sizeof(char));

	//Two sockets for this program. One to recieve and one to send traffic

	int recv_sock = socket(AF_INET,//AF_PACKET,
				SOCK_RAW,
				IPPROTO_TCP);//htons(ETHER_TYPE));//recieve	
	
	int send_sock = socket(AF_INET,
				SOCK_RAW,
				IPPROTO_RAW);//send

	const int on = 1;
	int status = setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));
	
	setsockopt(recv_sock, SOL_SOCKET,SO_REUSEADDR, &on, sizeof(int));
	setsockopt(send_sock, SOL_SOCKET,SO_REUSEADDR, &on, sizeof(int));	

	struct timeval *time_out = (struct timeval *)malloc(sizeof(struct timeval));
	//Configure the timeouts 
	time_out->tv_sec = 10;
	time_out->tv_usec = 0;

	setsockopt(recv_sock, SOL_SOCKET, SO_RCVTIMEO, (char *)time_out, sizeof(time_out));
	setsockopt(send_sock, SOL_SOCKET, SO_SNDTIMEO, (char *)time_out, sizeof(time_out));

	if(recv_sock < 0 || send_sock < 0){
		char *err_msg = "Failed to create a socket!";
		error(&err_msg);
	}
	
	//Parse the URL in order to build the IP packet
	url_parser_url_t *url_p = (url_parser_url_t*)malloc(sizeof(url_parser_url_t));
	char *ip_address = (char*)malloc(10*sizeof(char));

	parse_url(url,true,url_p);//,&ip);
	char *host = url_p->host;

	//Grab the ip address for the destination
	sprintf(ip_address,"%s",url_p->host_ip);

	//Building the IP packet
	
	//Get the sender's IP address
	char *src_addr = (char*)malloc(10*sizeof(char));
	ip_resolver(&src_addr);
	
	struct in_addr src, dst;
        inet_pton(AF_INET,src_addr,&(src));
        inet_pton(AF_INET,ip_address,&(dst));

	//Establish the three-way TCP handshake
	struct comparator *passed = (struct comparator*)malloc(sizeof(struct comparator));
	passed = establish_connection(send_sock,recv_sock,&ip_address,&src_addr);

	//Generate HTTP payload
	char *http_payload = (char*)malloc(50*sizeof(char));
	sprintf(http_payload, "GET %s HTTP/1.1\r\nHost: %s\r\n\r\n",url_p->path,host);
	printf("%s\n",http_payload);
	if(!strcmp(url_p->path,"/")){
		file_name = "index.html";
	}
	else{
		file_name = url_p->path;
	}
	//Send and Recieve the http data
	issue_get(http_payload,src,dst,&passed,send_sock);
	
	struct http_data *html = (struct http_data*)malloc(sizeof(struct http_data));
	get_tcp_payload(&html,recv_sock,send_sock,&passed,src,dst);
	
	//Close the connection
	close_connection(&passed,send_sock,recv_sock,src,dst);	

	FILE *fp;
	fp = fopen(file_name,"wb");
	fprintf(fp,"%s",html->payload);
	fclose(fp);

	close(send_sock);
	close(recv_sock);
}
