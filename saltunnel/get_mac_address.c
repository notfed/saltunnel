//
//  get_mac_address.c
//  saltunnel
//

#include "get_mac_address.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <ifaddrs.h>
#include <errno.h>

#if defined(HAVE_SIOCGIFHWADDR)
bool get_mac_address(char* mac_addr, const char* if_name = "eth0")
{
    struct ifreq ifinfo;
    strcpy(ifinfo.ifr_name, if_name);
    int sd = socket(AF_INET, SOCK_DGRAM, 0);
    int result = ioctl(sd, SIOCGIFHWADDR, &ifinfo);
    close(sd);

    if ((result == 0) && (ifinfo.ifr_hwaddr.sa_family == 1)) {
        memcpy(mac_addr, ifinfo.ifr_hwaddr.sa_data, IFHWADDRLEN);
        return true;
    }
    else {
        return false;
    }
}
#elif defined(__APPLE__)
int get_mac_address(unsigned char mac_addr[6])
{
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
#else
#   error no definition for get_mac_address() on this platform!
#endif
