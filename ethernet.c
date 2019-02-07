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
/*
This function comes from https://stackoverflow.com/questions/5457608/how-to-remove-the-character-at-a-given-index-from-a-string-in-c
*/
void remove_char(char *str, char garbage) {

    char *src, *dst;
    for (src = dst = str; *src != '\0'; src++) {
        *dst = *src;
        if (*dst != garbage) dst++;
    }
    *dst = '\0';
}

int build_socket_send(){

	int send_s;
	if((send_s = socket(AF_PACKET,SOCK_RAW,htons(ETHER_TYPE))) < 0){
		perror("send socket");
		exit(-1);
	}
	return send_s;
}

int build_socket_recv(){
	
	int recv_s;
	if((recv_s = socket(AF_PACKET,SOCK_RAW,htons(ETHER_TYPE))) < 0){
		perror("recv socket");
		exit(-1);
	}
	return recv_s;
}

char *get_mac(char *interface){
	char *dir_mac = (char*)malloc(sizeof(char)*30);
	struct sockaddr *ret_struct = (struct sockaddr*)malloc(sizeof(struct sockaddr));
	char *buffer = (char*)malloc(sizeof(char)*30);
	int status, fd;

	sprintf(dir_mac, "/sys/class/net/%s/address",interface);
	if((fd = open(dir_mac,O_RDONLY)) < 0){
		perror("open");
		exit(-1);
	}
	if((status = read(fd,buffer,20)) < 0){
		perror("read");
		exit(-1);
	}
	return buffer;
}

int main(){

	int send_s = build_socket_send();
	int recv_s = build_socket_recv();
	
	char *big_mac = get_mac("wlx00c0ca96b578");
	remove_char(big_mac,'\n');
	
	
	close(send_s);
	close(recv_s);
}
