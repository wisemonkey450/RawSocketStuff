#include "ip_build.h"
#include "tcp_build.h"
#include "struct_def.h"

//Issues our GET request to src containing http_payload data
void issue_get(char *http_payload, struct in_addr src, struct in_addr dst, struct comparator **passed, int send_it){
	struct ip *ip_http = (struct ip*)malloc(sizeof(struct ip));
        struct tcphdr *tcp_http = (struct tcphdr*)malloc(sizeof(struct tcphdr));

        generate_ip(&ip_http,0,src,dst);
        
	generate_tcp(&tcp_http,&ip_http,passed,TH_PUSH|TH_ACK,http_payload,(*passed)->their_pay);

	(*passed)->src_addr = ip_http->ip_src;
	(*passed)->dst_addr = ip_http->ip_dst;
	(*passed)->ip_checksum = 0;
	(*passed)->src_port = tcp_http->th_sport;
	(*passed)->dst_port = tcp_http->th_dport;
	(*passed)->tcp_checksum = 0;
	(*passed)->my_pay = http_payload;
	
        int finish_buffer_len = 0;
        char *finish_buffer = (char*)malloc(255*sizeof(char));
        memcpy(finish_buffer,ip_http,sizeof(struct ip));
        finish_buffer_len += sizeof(struct ip);

        memcpy((finish_buffer + sizeof(struct ip)),tcp_http,sizeof(struct tcphdr));
        finish_buffer_len += sizeof(struct tcphdr);

        memcpy((finish_buffer+sizeof(struct ip)+sizeof(struct tcphdr)),http_payload,(strlen(http_payload)*sizeof(uint8_t)));
        finish_buffer_len += strlen(http_payload);

        int status_s;
        struct sockaddr_in sin;
        memset (&sin, 0, sizeof (struct sockaddr_in));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = (ip_http->ip_dst).s_addr;
        
	if((status_s = sendto(send_it,finish_buffer,finish_buffer_len,0,(struct sockaddr *)&sin,sizeof(struct sockaddr))) < 0){
                perror("sendto");
                exit(-1);
        }
	//ONLY CHANGE SEQ IF YOU SEND!!
	uint32_t val = ntohl((*passed)->client->seq) + strlen(http_payload);
	(*passed)->client->seq = htonl(val);
}
