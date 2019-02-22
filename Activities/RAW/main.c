#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <ifaddrs.h>
#include <string.h>

uint16_t calc_check_sum (uint16_t *addr, int len){
    int count = len;
    uint32_t sum = 0;
    uint16_t answer = 0;

    while (count > 1) {
        sum += *(addr++);
        count -= 2;            
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return ~sum;
}

int main(int argc, char **argv){
    //Check for args
    /*if(argc < 2){
        printf("Error: Need some arguments\n");
        exit(-1);
    }*/

    struct ip *hdr = (struct ip*)malloc(sizeof(struct iphdr));
    struct ifaddrs *ioctl_addr;

    hdr->ip_hl = sizeof(struct iphdr)/sizeof(uint32_t);;
    hdr->ip_v = 4;
    hdr->ip_tos = 0;
    hdr->ip_len = sizeof(struct iphdr);
    hdr->ip_id = htons(10567);
    hdr->ip_ttl = 128;
    hdr->ip_p = IPPROTO_TCP;

    int *ip_bit_flags = (int*)malloc(4*sizeof(int));

    ip_bit_flags[0] = 0;//Zero
    ip_bit_flags[1] = 1;//Fragment?
    ip_bit_flags[2] = 0;//More fragments
    ip_bit_flags[3] = 0;//Offset 

    hdr->ip_off = htons((ip_bit_flags[0] << 15)
            + (ip_bit_flags[1] << 14) 
            + (ip_bit_flags[2] << 13) 
            + (ip_bit_flags[3]));

    //Get the TARGET IP address
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(7890);
    inet_pton(AF_INET, "10.1.0.3", &addr.sin_addr);

    //Get the SOURCE IP address
    struct sockaddr_in *src;
    getifaddrs(&ioctl_addr);
    struct ifaddrs *link;
    
    link=ioctl_addr;
    //Iterate through the linked list
    while(link != NULL){
        if(!strcmp(link->ifa_name,"eth0")){
            struct sockaddr_in * ipaddr = (struct sockaddr_in*)link->ifa_addr;
            if(ipaddr->sin_family == AF_INET){
                src = ipaddr;
                printf("[+] Found IP on %s which is %s\n", link->ifa_name, inet_ntoa(ipaddr->sin_addr));
            }   
        }

        link = link->ifa_next;
    }

    //Set the Source and Destiniation IPs with inet_pton
    hdr->ip_src = src->sin_addr;
    hdr->ip_dst = addr.sin_addr;

    //Calulate the IP Checksum
    hdr->ip_sum = calc_check_sum((unsigned short*)hdr, sizeof(struct iphdr));

    int sockfd;
    if((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP)) < 0){
        perror("socket");
        exit(-1);
    }

    int status;
    if((status = sendto(sockfd, (void*)hdr, sizeof(struct iphdr), 0, (struct sockaddr*)&addr, sizeof(struct iphdr)) < 0)){
        perror("send");
        exit(-1);
    }

    printf("[+] Successfully sent the packet!\n");
}
