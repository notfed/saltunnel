#include <sys/ioctl.h>
#include <net/if.h> 
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdio.h>

/*
int getmacosx() {
    const char* if_name = "en0";
    struct ifaddrs* iflist;
    int found = 0;
    if (getifaddrs(&iflist) == 0) {
        for (struct ifaddrs* cur = iflist; cur; cur = cur->ifa_next) {
            if ((cur->ifa_addr->sa_family == AF_LINK) &&
                    (strcmp(cur->ifa_name, if_name) == 0) &&
                    cur->ifa_addr) {
                struct sockaddr_dl* sdl = (struct sockaddr_dl*)cur->ifa_addr;
                memcpy(mac_addr, LLADDR(sdl), sdl->sdl_alen);
                found = 1;
                break;
            }
        }

        freeifaddrs(iflist);
    }
    return found;
}
*/

int getmac(unsigned char mac_address[6]) {
    struct ifreq ifr;
    struct ifconf ifc;
    char buf[1024];
    int success = 0;

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock == -1)
        return -1;

    ifc.ifc_len = sizeof(buf);
    ifc.ifc_buf = buf;
    if (ioctl(sock, SIOCGIFCONF, &ifc) == -1)
        return -1;

    struct ifreq* it = ifc.ifc_req;
    const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));

    for (; it != end; ++it) {
        strcpy(ifr.ifr_name, it->ifr_name);
        if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
            if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
                if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                    success = 1;
                    break;
                }
            }
        }
        else { 
            return -1; 
        }
    }

    if (success) memcpy(mac_address, ifr.ifr_hwaddr.sa_data, 6);

    return 0;
}

int main () {
   unsigned char mac_address[6] = {0};
   int r = getmac(mac_address);
   if(r<0)
     printf("failed to get MAC address\n");
   else
     printf("[%02X:%02X:%02X:%02X:%02X:%02X]\n", 
         mac_address[0], mac_address[1], mac_address[2], mac_address[3],
         mac_address[4], mac_address[5]);
   return 0;
}
