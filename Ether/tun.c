#include <fcntl.h>  /* O_RDWR */
#include <string.h> /* memset(), memcpy() */
#include <stdio.h> /* perror(), printf(), fprintf() */
#include <stdlib.h> /* exit(), malloc(), free() */
#include <unistd.h>
#include <sys/ioctl.h> /* ioctl() */

/* includes for struct ifreq, etc */
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>

#include "headers/tun.h"

int open_tun(char *dev){
    struct ifreq ifr;
    int fd, err;

    //Open the /dev/net/tun device
    //For Read / Writing
    if((fd = open("/dev/net/tun", O_RDWR)) < 0){
        perror("open");
        exit(-1);
    }

    memset(&ifr, 0, sizeof(ifr));

    ifr.ifr_flags = IFF_TUN;

    //Make an IOCTL request that will be able to
    //set the tun device
    if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
        perror("ioctl TUNSETIFF");
        exit(-1);
    }

    strcpy(dev, ifr.ifr_name);
    return fd;
}

void read_tun_print(int fd){
    //MTU size
    char buffer[1500];

    int read_status;
    while(1){
        read_status = read(fd, buffer, sizeof(buffer));
        
        if(read_status < 0){
            perror("Reading TUN");
            close(fd);
            exit(-1);
        }
       
        printf(RED"[DEBUG] Got some data: %s\n", buffer);
        printf(RESET);
        
    }
}
