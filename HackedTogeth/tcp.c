#include "tcp_build.h"
#include "ip_build.h"
#include "struct_def.h"

uint16_t calc_tcp_check_sum(struct tcphdr **my_tcp, struct ip **my_ip, int pay_len,int verf);
int verify(struct comparator **master, struct comparator **challenger,struct ip **ip_check,struct tcphdr **tcp_check);

char *tcp_payload;

int my_str_len(char *string){
	if(string == NULL){
		return 0;
	}
	else{
		return strlen(string);
	}
}

int process_recv_tcp(struct comparator **cmp,struct tcphdr **recv_tcp, struct ip **recv_ip){
	//ONLY CHANGE YOUR YOUR ACK!
	if(!(((*recv_tcp)->th_flags) ^ (TH_ACK))){
		((*cmp)->server)->seq = (*recv_tcp)->th_seq;
		
		(*cmp)->server->ack = (*recv_tcp)->th_ack;
		return TH_ACK;
	}
	else if((((*recv_tcp)->th_flags) & 0xf7)){// && ((*recv_tcp)->th_flags & 0xfe)){//Got a PSH -- SOME DATA! CHANGE ACK
		int val = ntohl((*cmp)->client->ack);
		val += strlen(tcp_payload);
		(*cmp)->client->ack = htonl(val);
		
		(*cmp)->server->seq = (*recv_tcp)->th_seq;
                (*cmp)->server->ack = (*recv_tcp)->th_ack;
		
		return TH_PUSH;
	}
	else if((*recv_tcp)->th_flags & 0xfe){//Got a FIN
		int val = ntohl((*cmp)->client->ack);
                val += strlen(tcp_payload);
                (*cmp)->client->ack = htonl(val);
                return TH_FIN;
	}
	else{
		return 0;
	}
}

void send_ack(struct comparator **cmp, int send_it, struct in_addr src, struct in_addr dst){
	struct ip *ip_ack = (struct ip*)malloc(sizeof(struct ip));
        struct tcphdr *tcp_ack = (struct tcphdr*)malloc(sizeof(struct tcphdr));

	generate_ip(&ip_ack,0,src,dst);

	generate_tcp(&tcp_ack,&ip_ack,cmp,TH_ACK,NULL,NULL);
	
	(*cmp)->src_addr = ip_ack->ip_src;
        (*cmp)->dst_addr = ip_ack->ip_dst;
        (*cmp)->ip_checksum = 0;
        (*cmp)->src_port = tcp_ack->th_sport;
        (*cmp)->dst_port = tcp_ack->th_dport;
        (*cmp)->tcp_checksum = 0;

	int finish_buffer_len = 0;
        char *finish_buffer = (char*)malloc(255*sizeof(char));
        memcpy(finish_buffer,ip_ack,sizeof(struct ip));
        finish_buffer_len += sizeof(struct ip);

        memcpy((finish_buffer + sizeof(struct ip)),tcp_ack,sizeof(struct tcphdr));
        finish_buffer_len += sizeof(struct tcphdr);

	int status_s;
        struct sockaddr_in sin;
        memset (&sin, 0, sizeof (struct sockaddr_in));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = (ip_ack->ip_dst).s_addr;

        if((status_s = sendto(send_it,finish_buffer,finish_buffer_len,0,(struct sockaddr *)&sin,sizeof(struct sockaddr))) < 0){
                perror("sendto");
                exit(-1);
        }
	
	//DID NOT SEND PAYLOAD SO DO NOT CHANGE SEQ NUMBERS!

}

void send_fin_ack(struct comparator **cmp, int send_it, struct in_addr src, struct in_addr dst){
        struct ip *ip_fin_ack = (struct ip*)malloc(sizeof(struct ip));
        struct tcphdr *tcp_fin_ack = (struct tcphdr*)malloc(sizeof(struct tcphdr));

        generate_ip(&ip_fin_ack,0,src,dst);

        //int val = ntohl((*cmp)->client->seq);
        //val += 1;
        //(*cmp)->client->seq = htonl(val);

	generate_tcp(&tcp_fin_ack,&ip_fin_ack,cmp,TH_ACK|TH_FIN,NULL,NULL);

        (*cmp)->src_addr = ip_fin_ack->ip_src;
        (*cmp)->dst_addr = ip_fin_ack->ip_dst;
        (*cmp)->ip_checksum = 0;
        (*cmp)->src_port = tcp_fin_ack->th_sport;
        (*cmp)->dst_port = tcp_fin_ack->th_dport;
        (*cmp)->tcp_checksum = 0;

        int finish_buffer_len = 0;
        char *finish_buffer = (char*)malloc(255*sizeof(char));
        memcpy(finish_buffer,ip_fin_ack,sizeof(struct ip));
        finish_buffer_len += sizeof(struct ip);

        memcpy((finish_buffer + sizeof(struct ip)),tcp_fin_ack,sizeof(struct tcphdr));
        finish_buffer_len += sizeof(struct tcphdr);

        int status_s;
        struct sockaddr_in sin;
        memset (&sin, 0, sizeof (struct sockaddr_in));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = (ip_fin_ack->ip_dst).s_addr;

        if((status_s = sendto(send_it,finish_buffer,finish_buffer_len,0,(struct sockaddr *)&sin,sizeof(struct sockaddr))) < 0){
                perror("sendto");
                exit(-1);
        }

        //DID NOT SEND PAYLOAD SO DO NOT CHANGE SEQ NUMBERS!
}

void close_connection(struct comparator **cmp, int send_it, int get_it, struct in_addr src, struct in_addr dst){
	send_fin_ack(cmp,send_it,src,dst);
	//int val = ntohl((*cmp_tcp)->client->ack);
        //val += (ntohl((*cmp_tcp)->server->seq) + 1);
        //(*cmp_tcp)->client->ack = htonl(val);
	
	struct comparator *challenger = (struct comparator *)malloc(sizeof(struct comparator));
        int recv_status;
        char recv_buffer[65535];// = (char*)malloc(1024*sizeof(char));

        struct ip *recv_ip_hold = (struct ip *)malloc(sizeof(struct ip));
        struct tcphdr *recv_tcp_hold = (struct tcphdr *)malloc(sizeof(struct tcphdr));
        memset(&(recv_buffer),'\0',65535);
        while(1){
                //Recieve the packet
                if((recv_status = recv(get_it,&recv_buffer,65535,0)) == -1){
                        perror("recv");
                        exit(-1);
                }
                //Cast as an ip header
                recv_ip_hold = (struct ip*)recv_buffer;
                //Grab the IP values
                challenger->src_addr = recv_ip_hold->ip_src;
                challenger->dst_addr = recv_ip_hold->ip_dst;
                challenger->ip_checksum = recv_ip_hold->ip_sum;
                //Cast as a tcp header  
                recv_tcp_hold = (struct tcphdr*)(recv_buffer + sizeof(struct ip));
                challenger->src_port = recv_tcp_hold->th_sport;
                challenger->dst_port = recv_tcp_hold->th_dport;
                challenger->seq = recv_tcp_hold->th_seq;
                challenger->ack = recv_tcp_hold->th_ack;
                challenger->tcp_checksum = recv_tcp_hold->th_sum;
                challenger->flags = recv_tcp_hold->th_flags;
                tcp_payload = (recv_buffer+(sizeof(struct tcphdr)+sizeof(struct iphdr)));

		if(!verify(cmp,&challenger,&recv_ip_hold,&recv_tcp_hold) && ((challenger->flags & 0x01) == 0x01)){
			break;
                }
                else{
                        continue;
                }

        }
	int val = ntohl((*cmp)->client->ack);
	val += 1;
	(*cmp)->client->ack = htonl(val); 

	int tie = ntohl((*cmp)->client->seq);
	tie += 1;
	(*cmp)->client->seq = htonl(tie);

	send_ack(cmp,send_it,src,dst);
}

void get_tcp_payload(struct http_data **data,int socket, int send_sock, struct comparator **cmp_tcp, struct in_addr src, struct in_addr dst){
	char return_buffer[65535]; 
	char *offset = (char*)malloc(sizeof(char)*65535);
	offset = &return_buffer[0];
	int recv_status;
        char recv_buffer[65535];// = (char*)malloc(65535);
        char *payloader = (char*)malloc(2048);
        struct ip *recv_ip_hold = (struct ip *)malloc(sizeof(struct ip));
        struct tcphdr *recv_tcp_hold = (struct tcphdr *)malloc(sizeof(struct tcphdr));
        struct comparator *challenger = (struct comparator *)malloc(sizeof(struct comparator));

        memset(&(recv_buffer),'\0',65535);
        while(1){
                //Recieve the packet
                if((recv_status = recv(socket,&recv_buffer,65535,0)) == -1){
                        perror("recv");
                        exit(-1);
                }
                //Cast as an ip header
                recv_ip_hold = (struct ip*)recv_buffer;
                //Grab the IP values
                challenger->src_addr = recv_ip_hold->ip_src;
                challenger->dst_addr = recv_ip_hold->ip_dst;
                challenger->ip_checksum = recv_ip_hold->ip_sum;
                //Cast as a tcp header  
                recv_tcp_hold = (struct tcphdr*)(recv_buffer + sizeof(struct ip));
                challenger->src_port = recv_tcp_hold->th_sport;
                challenger->dst_port = recv_tcp_hold->th_dport;
                challenger->seq = recv_tcp_hold->th_seq;
                challenger->ack = recv_tcp_hold->th_ack;
                challenger->tcp_checksum = recv_tcp_hold->th_sum;
                challenger->flags = recv_tcp_hold->th_flags;
                tcp_payload = (char*)(recv_buffer+(sizeof(struct tcphdr)+sizeof(struct iphdr)));
                int flag_stat = 0;

		if(!verify(cmp_tcp,&challenger,&recv_ip_hold,&recv_tcp_hold)){

			flag_stat = process_recv_tcp(cmp_tcp,&recv_tcp_hold,&recv_ip_hold);
			uint8_t flag;
	
			flag = recv_tcp_hold->th_flags;	
			if(flag & TH_PUSH == TH_PUSH){
				memcpy(offset,tcp_payload,strlen(tcp_payload));
                                offset += strlen(tcp_payload);
                                send_ack(cmp_tcp,send_sock,src,dst);
			}	
			if(flag & TH_FIN == TH_FIN ){
				(*data)->payload = return_buffer;
				return;
			}
			if(flag & TH_ACK == TH_ACK){
					//send_ack(cmp_tcp,send_sock,src,dst);
				memcpy(offset,tcp_payload,strlen(tcp_payload));
                                offset += strlen(tcp_payload);
                                send_ack(cmp_tcp,send_sock,src,dst);
			}
			

		/*	if(flag_stat == TH_PUSH){
				if(flag_stat == TH_FIN || ((recv_tcp_hold->th_flags & 0x01)==0x01)){
					memcpy(offset,tcp_payload,strlen(tcp_payload));
                                	offset += strlen(tcp_payload);
					send_fin_ack(cmp_tcp,send_sock,src,dst);
					int val = ntohl((*cmp_tcp)->client->ack);
                			val += (ntohl((*cmp_tcp)->server->seq) + 1);
                			(*cmp_tcp)->client->ack = htonl(val);
                                	
					send_ack(cmp_tcp,send_sock,src,dst);
					break;
				}
				memcpy(offset,tcp_payload,strlen(tcp_payload));
                                offset += strlen(tcp_payload);
                                //printf("%s\t%s\n",tcp_payload,return_buffer);
				send_ack(cmp_tcp,send_sock,src,dst);
			}
			else if(flag_stat == TH_FIN || ((recv_tcp_hold->th_flags & 0x01)==0x01)){
				printf("%d\n",offset);
				memcpy((offset),tcp_payload,strlen(tcp_payload));
                                offset += strlen(tcp_payload);
                                send_ack(cmp_tcp,send_sock,src,dst);
				break;
			}
			else{
				if(flag_stat == TH_ACK){
					continue;
				}
				else{
					printf("%d\n",offset);
					memcpy((offset),tcp_payload,strlen(tcp_payload));
					offset += strlen(tcp_payload);
					send_ack(cmp_tcp,send_sock,src,dst);
				}
			}*/
		}
        }
	(*data)->payload = return_buffer;
}

int end_tcp(char *buffer){

	int end = strlen(buffer);
	char* ptr = (buffer + end)-7;
	
	for(int i = 0; i < 7; i++){
		*(ptr+i) = tolower(*(ptr+i));
	}
	return strcmp("</html>",ptr);

}

void generate_tcp(struct tcphdr **gen_tcp, struct ip ** gen_ip, struct comparator **cmp, uint8_t flags, char *payload, char *their_payload){
	if(payload != NULL){
		tcp_payload = payload;
	}
	(*gen_tcp)->th_sport = (*cmp)->src_port;
	(*gen_tcp)->th_dport = (*cmp)->dst_port;
	(*gen_tcp)->th_seq = (*cmp)->client->seq;
	(*gen_tcp)->th_ack = (*cmp)->client->ack;// + htonl(strlen(tcp_payload));
	(*gen_tcp)->th_x2 = 0;
	(*gen_tcp)->th_off = sizeof(struct tcphdr)/4;
	(*gen_tcp)->th_flags = flags;
	(*gen_tcp)->th_win = 65535;
	(*gen_tcp)->th_urp = 0;
	(*gen_tcp)->th_sum = 0;
	if(payload != NULL){
		(*gen_tcp)->th_sum = calc_tcp_check_sum(gen_tcp, gen_ip, strlen(tcp_payload),0);
	}
	else{
		(*gen_tcp)->th_sum = calc_tcp_check_sum(gen_tcp, gen_ip, 0, 0);
	}
}

struct comparator *establish_connection(int raw_send, int raw_recv, char **dst_addr, char **src_addr){
	/*********************SEND THE SYN**********************/
	//Building the IP packet 
	//We have to have a sender buffer. It is just some bytes we are sending afterall
        unsigned char *buff_byte = (unsigned char*)malloc(96);
        //Length of buff_byte
        int length = 0;
	int send_status;
        int *ip_bit_flags = (int*)malloc(4*sizeof(int));

	struct client_nums *my_nums = (struct client_nums *)malloc(sizeof(struct client_nums));
	struct server_nums *their_nums = (struct server_nums *)malloc(sizeof(struct server_nums));

        ip_bit_flags[0] = 0;//Zero
        ip_bit_flags[1] = 1;//Fragment?
        ip_bit_flags[2] = 0;//More fragments
        ip_bit_flags[3] = 0;//Offset 

        struct ip *my_ip = (struct ip*)malloc(sizeof(struct iphdr));//(struct iphdr*)buff_byte;
        //Poulating the header
        my_ip->ip_hl = sizeof(struct iphdr) / sizeof(uint32_t);
        my_ip->ip_v = 4;
        my_ip->ip_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        my_ip->ip_tos = 0;
        my_ip->ip_id = htons(10567);
        my_ip->ip_ttl = 64;
        my_ip->ip_p = IPPROTO_TCP;//We want TCP

        my_ip->ip_off = htons((ip_bit_flags[0] << 15)
                        + (ip_bit_flags[1] << 14)
                        + (ip_bit_flags[2] << 13)
                        + (ip_bit_flags[3]));

        inet_pton(AF_INET,*src_addr,&(my_ip->ip_src));
        inet_pton(AF_INET,*dst_addr,&(my_ip->ip_dst));

        my_ip->ip_sum = 0;
        my_ip->ip_sum = calc_check_sum((unsigned short*)my_ip,sizeof(struct iphdr));
	
	memcpy(buff_byte,my_ip,sizeof(struct iphdr));
        length += sizeof(struct iphdr);

        //Building the TCP packet
        struct tcphdr *my_tcp = (struct tcphdr*)(buff_byte + sizeof(struct iphdr));
        //Populating the header

        my_tcp->th_sport = htons(35768);
	my_tcp->th_dport = htons(80);
        my_tcp->th_seq = htonl(random() % 65535);//Sequence number generated randomly 
        my_tcp->th_ack = htonl(0);
        my_tcp->th_x2 = 0;
        my_tcp->th_off = sizeof(struct tcphdr)/4;
        my_tcp->th_flags = TH_SYN;
        my_tcp->th_win = htons(65535);
        my_tcp->th_urp = htons(0);
        my_tcp->th_sum = 0;
        my_tcp->th_sum = calc_tcp_check_sum(&my_tcp,&my_ip,0,0);

	my_nums->seq = my_tcp->th_seq;
	my_nums->ack = my_tcp->th_ack;

        memcpy((buff_byte+sizeof(struct iphdr)),my_tcp,sizeof(struct tcphdr));
        length += sizeof(struct tcphdr);
        
	struct sockaddr_in sin;
        memset (&sin, 0, sizeof (struct sockaddr_in));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = (my_ip->ip_dst).s_addr;
        if((send_status = sendto(raw_send,buff_byte,length,0,(struct sockaddr *)&sin,sizeof(struct sockaddr))) < 0){
		perror("sendto");
		exit(-1);
	}
	/**********MASTER COMPARATOR**********/
	struct comparator *cmp = (struct comparator *)malloc(sizeof(struct comparator));
	cmp->src_addr = my_ip->ip_src;
	cmp->dst_addr = my_ip->ip_dst;
	cmp->ip_checksum = 0;//For now. We will populate when we have recieved the full packet from the server in SYN-ACK
	cmp->src_port = my_tcp->th_sport;
	cmp->dst_port = my_tcp->th_dport;
	cmp->seq = my_tcp->th_seq;
	cmp->ack = my_tcp->th_ack;
	cmp->tcp_checksum = 0;//For now. Same as above. Will verify later.
	/*************************************/
	


	/*************************RECVIEVE THE SYN-ACK***************************/
	struct comparator *challenger = (struct comparator *)malloc(sizeof(struct comparator));	
	int recv_status;
	char recv_buffer[65535];// = (char*)malloc(1024*sizeof(char));
	
	struct ip *recv_ip_hold = (struct ip *)malloc(sizeof(struct ip));
	struct tcphdr *recv_tcp_hold = (struct tcphdr *)malloc(sizeof(struct tcphdr));
	memset(&(recv_buffer),'\0',65535);
	while(1){
		//Recieve the packet
		if((recv_status = recv(raw_recv,&recv_buffer,65535,0)) == -1){
	 		perror("recv");
			exit(-1);
		}
		//Cast as an ip header
		recv_ip_hold = (struct ip*)recv_buffer;
		//Grab the IP values
		challenger->src_addr = recv_ip_hold->ip_src;
		challenger->dst_addr = recv_ip_hold->ip_dst;
		challenger->ip_checksum = recv_ip_hold->ip_sum;
		//Cast as a tcp header	
		recv_tcp_hold = (struct tcphdr*)(recv_buffer + sizeof(struct ip));
		challenger->src_port = recv_tcp_hold->th_sport;
		challenger->dst_port = recv_tcp_hold->th_dport;
		challenger->seq = recv_tcp_hold->th_seq;
		challenger->ack = recv_tcp_hold->th_ack;
		challenger->tcp_checksum = recv_tcp_hold->th_sum;
		challenger->flags = recv_tcp_hold->th_flags;		
		tcp_payload = (recv_buffer+(sizeof(struct tcphdr)+sizeof(struct iphdr)));
		printf("%d\n",recv_tcp_hold->th_off);
		if(!verify(&cmp,&challenger,&recv_ip_hold,&recv_tcp_hold) && !(challenger->flags ^ (TH_SYN | TH_ACK))){
			break;
		}
		else{
			continue;
		}

	}

	their_nums->seq = recv_tcp_hold->th_seq;
	their_nums->ack = recv_tcp_hold->th_ack;

	//We now have the SYN-ACK in recv_ip_hold and recv_tcp_hold
	/**************************SENDING THE ACK*****************************/
	char *return_buffer = (char*)malloc(sizeof(struct ip) + sizeof(struct tcphdr));
	struct ip *ret_ip = (struct ip *)malloc(sizeof(struct ip));
	struct tcphdr *ret_tcp = (struct tcphdr *)malloc(sizeof(struct tcphdr));
	int return_len = 0;
	
	//Populate ret_ip
	ret_ip->ip_hl = sizeof(struct iphdr) / sizeof(uint32_t);
        ret_ip->ip_v = 4;
        ret_ip->ip_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
        ret_ip->ip_tos = 0;
        ret_ip->ip_id = htons(10567);
        ret_ip->ip_ttl = 64;
        ret_ip->ip_p = IPPROTO_TCP;//We want TCP

        ret_ip->ip_off = htons((ip_bit_flags[0] << 15)
                        + (ip_bit_flags[1] << 14)
                        + (ip_bit_flags[2] << 13)
			+ (ip_bit_flags[3]));

	ret_ip->ip_src = recv_ip_hold->ip_dst;
	ret_ip->ip_dst = recv_ip_hold->ip_src;

	ret_ip->ip_sum=0;
	ret_ip->ip_sum = calc_check_sum((unsigned short*)ret_ip,sizeof(struct iphdr));
	
	//Copy ret_ip into return_buffer
	memcpy(return_buffer,ret_ip,sizeof(struct iphdr));
	return_len += sizeof(struct ip);

	//Populate ret_tcp
	ret_tcp->th_sport = recv_tcp_hold->th_dport;
        ret_tcp->th_dport = recv_tcp_hold->th_sport;
        ret_tcp->th_seq = my_tcp->seq + htonl(1);
        ret_tcp->th_ack = recv_tcp_hold->seq + htonl(1);
        ret_tcp->th_x2 = 0;
        ret_tcp->th_off = sizeof(struct tcphdr)/4;
        ret_tcp->th_flags = TH_ACK;
        ret_tcp->th_win = htons(65535);
        ret_tcp->th_urp = htonl(0);
        ret_tcp->th_sum = 0;
        ret_tcp->th_sum = calc_tcp_check_sum(&ret_tcp,&ret_ip,0,0);

	my_nums->seq = ret_tcp->th_seq;
	my_nums->ack = ret_tcp->th_ack;

	//Copy ret_tcp into return_buffer with the proper offset
	memcpy((return_buffer + sizeof(struct iphdr)),ret_tcp,sizeof(struct tcphdr));
	return_len += sizeof(struct tcphdr);

	//Send the ACK
	struct sockaddr_in ret_sin;
        memset (&ret_sin, 0, sizeof (struct sockaddr_in));
        ret_sin.sin_family = AF_INET;
        ret_sin.sin_addr.s_addr = (my_ip->ip_dst).s_addr;
        if((send_status = sendto(raw_send,return_buffer,return_len,0,(struct sockaddr *)&ret_sin,sizeof(struct sockaddr))) < 0){
		perror("sendto");
		exit(-1);
	}
	/**************RETURN A COMPARATOR STRUCT****************/
	struct comparator *ret_cmp = (struct comparator*)malloc(sizeof(struct comparator));
	
	ret_cmp->src_addr = ret_ip->ip_src;
	ret_cmp->dst_addr = ret_ip->ip_dst;
	ret_cmp->ip_checksum = 0;
	ret_cmp->src_port = ret_tcp->th_sport;
	ret_cmp->dst_port = ret_tcp->th_dport;
	ret_cmp->seq = ret_tcp->th_seq;
	ret_cmp->ack = ret_tcp->th_ack;
	ret_cmp->tcp_checksum = 0;
	//printf(" -- %d -- \n",recv_tcp_hold->th_off);
	ret_cmp->their_pay = (return_buffer + (recv_tcp_hold->th_off * 4) + sizeof(struct iphdr));
	ret_cmp->client = my_nums;
	ret_cmp->server = their_nums;
	//printf("%08x\n",
	//printf("%d ---- %d\n",ret_cmp->src_port,ret_cmp->dst_port);
	return ret_cmp;
}

int verify(struct comparator **master, struct comparator **challenger,struct ip **ip_check,struct tcphdr **tcp_check){
	int first = memcmp((void*)&(*master)->src_addr,(void*)&(*challenger)->dst_addr,sizeof((*master)->src_addr));
	//printf("1 %d\n",first);
	int second = memcmp((void*)&(*master)->dst_addr,(void*)&(*challenger)->src_addr,sizeof((*master)->src_addr));
	//printf("2 %d\n",second);
	uint16_t third = calc_check_sum((unsigned short*)(*ip_check),sizeof(struct iphdr));
	//printf("3 %d\n",third);
	uint16_t fourth = calc_tcp_check_sum(tcp_check,ip_check,my_str_len(tcp_payload),1);	
	//printf("4 %d\n",fourth);
	int fifth = memcmp((void*)&(*master)->src_port,(void*)&(*challenger)->dst_port,sizeof((*master)->src_port));
	//printf("5 %d\n",fifth);

	return first | second | third | fourth | fifth;
}

uint16_t calc_tcp_check_sum(struct tcphdr **my_tcp, struct ip **my_ip, int pay_len, int verf){
	char *psd_hdr = (char*)malloc((int) pay_len+sizeof(struct p_tcp_hdr) + sizeof(struct tcphdr));
	char psd_buff[32+pay_len];
	int sum_len = 0;

	psd_hdr = &psd_buff[0];

	memcpy(psd_hdr, &(*my_ip)->ip_src, sizeof((*my_ip)->ip_src));
	psd_hdr += sizeof((*my_ip)->ip_src);
	sum_len += sizeof((*my_ip)->ip_src);
	
	memcpy(psd_hdr, &((*my_ip))->ip_dst, sizeof((*my_ip)->ip_dst));
        psd_hdr += sizeof((*my_ip)->ip_dst);
        sum_len += sizeof((*my_ip)->ip_dst);

	*psd_hdr = 0;
	psd_hdr++;
	sum_len += 1;

	memcpy(psd_hdr,&(*my_ip)->ip_p,sizeof((*my_ip)->ip_p));
	psd_hdr += sizeof((*my_ip)->ip_p);
	sum_len += sizeof((*my_ip)->ip_p);
	
	uint16_t tcp_len_val = htons(sizeof(struct tcphdr) + pay_len);
	memcpy(psd_hdr, &(tcp_len_val), sizeof(tcp_len_val));
	psd_hdr += sizeof(tcp_len_val);
	sum_len += sizeof(tcp_len_val);

	memcpy(psd_hdr, &(*my_tcp)->th_sport, sizeof((*my_tcp)->th_sport));
	psd_hdr += sizeof((*my_tcp)->th_sport);
	sum_len += sizeof((*my_tcp)->th_sport);
	
  	memcpy (psd_hdr, &(*my_tcp)->th_dport, sizeof ((*my_tcp)->th_dport));
  	psd_hdr += sizeof ((*my_tcp)->th_dport);
  		sum_len += sizeof ((*my_tcp)->th_dport);

	memcpy (psd_hdr, &(*my_tcp)->th_seq, sizeof ((*my_tcp)->th_seq));
 	psd_hdr += sizeof ((*my_tcp)->th_seq);
  	sum_len += sizeof ((*my_tcp)->th_seq);

  	memcpy (psd_hdr, &(*my_tcp)->th_ack, sizeof ((*my_tcp)->th_ack));
  	psd_hdr += sizeof ((*my_tcp)->th_ack);
  	sum_len += sizeof ((*my_tcp)->th_ack);

  	char cvalue = ((*my_tcp)->th_off << 4) + (*my_tcp)->th_x2;
  	memcpy (psd_hdr, &cvalue, sizeof (cvalue));
  	psd_hdr += sizeof (cvalue);
  	sum_len += sizeof (cvalue);

  	memcpy (psd_hdr, &(*my_tcp)->th_flags, sizeof ((*my_tcp)->th_flags));
  	psd_hdr += sizeof ((*my_tcp)->th_flags);
  	sum_len += sizeof ((*my_tcp)->th_flags);

  	memcpy (psd_hdr, &(*my_tcp)->th_win, sizeof ((*my_tcp)->th_win));
  	psd_hdr += sizeof ((*my_tcp)->th_win);
  	sum_len += sizeof ((*my_tcp)->th_win);
  	
	if(verf){
		memcpy(psd_hdr, &((*my_tcp)->th_sum),sizeof((*my_tcp)->th_sum));
		psd_hdr += sizeof((*my_tcp)->th_sum);
		sum_len += sizeof((*my_tcp)->th_sum);
	}
	else{
		*psd_hdr = 0; psd_hdr++;
 		*psd_hdr = 0; psd_hdr++;
 		sum_len += 2;
	}

  	memcpy (psd_hdr, &(*my_tcp)->th_urp, sizeof ((*my_tcp)->th_urp));
  	psd_hdr += sizeof ((*my_tcp)->th_urp);
  	sum_len += sizeof ((*my_tcp)->th_urp);
	
	if(pay_len > 0){
		memcpy(psd_hdr, tcp_payload, pay_len);
		psd_hdr += pay_len;
		sum_len += pay_len;
	}
	for (int i=0; i<sum_len%2; i++, psd_hdr++) {
		*psd_hdr = 0;
		psd_hdr++;
    		sum_len++;
  	}
	return calc_check_sum((unsigned short*)psd_buff,sum_len);
}
