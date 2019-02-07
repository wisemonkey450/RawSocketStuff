#include "ip_build.h"

uint16_t calc_check_sum (uint16_t *addr, int len);

void generate_ip(struct ip **gen_ip, int flags, struct in_addr src, struct in_addr dst){
	(*gen_ip)->ip_hl = sizeof(struct iphdr)/sizeof(uint32_t);
	(*gen_ip)->ip_v = 4;
	(*gen_ip)->ip_tos = 0;
	(*gen_ip)->ip_id = htons(10567);
	(*gen_ip)->ip_ttl = 64;
	(*gen_ip)->ip_p = IPPROTO_TCP;
	
	int *ip_bit_flags = (int*)malloc(4*sizeof(int));

        ip_bit_flags[0] = 0;//Zero
        ip_bit_flags[1] = 1;//Fragment?
        ip_bit_flags[2] = 0;//More fragments
        ip_bit_flags[3] = 0;//Offset 

	(*gen_ip)->ip_off = htons((ip_bit_flags[0] << 15)
                        + (ip_bit_flags[1] << 14)
                        + (ip_bit_flags[2] << 13)
                        + (ip_bit_flags[3]));
	
	(*gen_ip)->ip_src = src;
	(*gen_ip)->ip_dst = dst;
	(*gen_ip)->ip_sum = 0;
	(*gen_ip)->ip_sum = calc_check_sum((unsigned short*)(*gen_ip),sizeof(struct iphdr));
}

void ip_resolver(char** address){
	struct ifaddrs *iface_addrs;
	char *iface = "wlx00c0ca96b578";
	
	if((getifaddrs(&iface_addrs)) < 0){
		return;
	}
	
	struct ifaddrs *curr_iface = iface_addrs;
	while(curr_iface){
		if(strcmp(curr_iface->ifa_name,iface) == 0){
			struct sockaddr_in * in = ((struct sockaddr_in*)curr_iface->ifa_addr);
			char *addr = inet_ntoa(in->sin_addr);
			short y = in->sin_family;
			if(y == AF_INET){//We want only the address that we can put into packets
				int sec_len = strlen(addr);
				sprintf(*address,"%s",addr);
			}
		}
		curr_iface = curr_iface->ifa_next;
	}
}
//Used the uint types in order to be more precise 
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
