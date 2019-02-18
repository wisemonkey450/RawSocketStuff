#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <arpa/inet.h> 
#include <sys/select.h>
#include <sys/time.h>
#include <errno.h>
#include <stdarg.h>

#include "headers/tun.h"

int main(int argc, char ** argv){
    //Device name, probably gonna be
    //tun0 but who knows right?
    char *dev_name = (char*)malloc(sizeof(char)*20);
    if(!dev_name){
        perror("malloc");
        exit(-1);
    }
    
    //Open the device
    //We want TUN because it gives us the 
    //access to the ethernet headers :)
    int fd = open_tun(dev_name);
    //Show the device
    
    printf(YEL"[DEBUG] Openned Device named: %s\n"RESET, dev_name);

    read_tun_print(fd);

    //Cleanup nice and neatly
    close(fd);

}
