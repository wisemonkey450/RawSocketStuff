#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <stdbool.h>

#ifndef URL_PARSE_
#define URL_PARSE_

/*

THIS CODE IS TAKEN FROM https://github.com/jaysonsantos/url-parser-c/blob/master/url_parser.c
I MODIFIED IT A LITTLE BUT IT STILL BELONGS TO @jaysonsantos

*/
typedef struct url_parser_url {
        char *protocol;
        char *host;
        int port;
        char *path;
        char *query_string;
        int host_exists;
        char *host_ip;
} url_parser_url_t;

void free_parsed_url(url_parser_url_t*);
int parse_url(char*,bool,url_parser_url_t*);//,char**);

#endif //URL_PARSE_
