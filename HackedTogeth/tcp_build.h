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
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <ctype.h>

#ifdef _TCP_BUILD
#define _TCP_BUILD

//Function defintions
//CHECKSUM COMPUTATION
uint16_t calc_tcp_check_sum(struct tcphdr **my_tcp, struct ip **my_ip, char* payload, int pay_len);

//FILTER FOR PROMISCUOUS MODE
int verify(struct comparator **master, struct comparator **challenger,struct ip **ip_check,struct tcphdr **tcp_check);

//strlen
int my_str_len;

//Process incoming TCP
int process_recv_tcp(struct comparator **cmp,struct tcphdr **recv_tcp, struct ip **recv_ip);

//Send ACK
void send_ack(struct comparator **cmp, int send_it, struct in_addr src, struct in_addr dst);

//Send FIN-ACK
void send_fin_ack(struct comparator **cmp, int send_it, struct in_addr src, struct in_addr dst);

//Connection tear down
void close_connection(struct comparator **cmp, int send_it, int get_it, struct in_addr src, struct in_addr dst);

//Get the TCP payload and deliver to higher layer
void get_tcp_payload(struct http_data **data,int socket, int send_sock, struct comparator **cmp_tcp, struct in_addr src, struct in_addr dst);

//End of the buffer
int end_tcp(char *buffer);

//Return a built TCP packet to struct tcphdr **gen_tcp
void generate_tcp(struct tcphdr **gen_tcp, struct ip ** gen_ip, struct comparator **cmp, uint8_t flags, char *payload, char *their_payload);

//Conducts the 3-way handshake process
struct comparator *establish_connection(int raw_send, int raw_recv, char **dst_addr, char **src_addr);

#endif //_TCP_BUILD
