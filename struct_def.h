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

struct client_nums {
  tcp_seq seq;
  tcp_seq ack;
};

struct server_nums {
  tcp_seq seq;
  tcp_seq ack;
};

struct p_tcp_hdr {
  struct in_addr srcAddr;
  struct in_addr dstAddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t TCP_len;
};

struct comparator {
  struct in_addr src_addr, dst_addr;
  u_short ip_checksum;
  uint16_t src_port;
  uint16_t dst_port;
  tcp_seq seq;
  tcp_seq ack;
  uint16_t tcp_checksum;
  uint8_t flags;
  char *their_pay;
  char *my_pay;
  struct client_nums* client;
  struct server_nums* server;
};

struct http_data {
  char *payload;
  int code;
};


