//
//  hypercounter.c
//  saltunnel
//

#include "hypercounter.h"
#include "uint64.h"
#include "sodium.h"

#include <time.h>
#include <errno.h>
#include <sys/sysctl.h>
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
#include <mach/clock.h>
#include <mach/mach.h>
#include <sys/sysctl.h>
#include <stdio.h>
#include <time.h>

static int get_boot_time(uint64_t* out_boot_time) {
    struct timeval boottime;
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    size_t size = sizeof(boottime);
    int rc = sysctl(mib, 2, &boottime, &size, NULL, 0);
    if (rc != 0) {
      return -1;
    }
    *out_boot_time = (uint64_t)boottime.tv_sec * 1000000 + (uint64_t)boottime.tv_usec;
    return 0;
}

static int get_monotonic_time_since_boot(uint64_t* monotonic_time_out) {
    struct timespec time;
    if(clock_gettime(CLOCK_REALTIME, &time)<0)
        return -1;
    *monotonic_time_out = (uint64_t)time.tv_sec * 1000000 + (uint64_t)time.tv_nsec;
    return 0;
}


#if defined(HAVE_SIOCGIFHWADDR)
static bool get_mac_address(char* mac_addr, const char* if_name = "eth0")
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
static int get_mac_address(unsigned char mac_addr[6])
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

int hypercounter(unsigned char machine_id_out[16], unsigned char monotonic_time_out[8]) {
    
    // Calculate machine_id
    unsigned char mac_addr[8] = {0};
    uint64_t boot_time;
    if(get_mac_address(mac_addr)<0)
        return -1;
    if(get_boot_time(&boot_time)<0)
        return -1;
    
    // TODO: Hash {mac_addr,boot_time} (?)
    
    // Calculate monotonic_time_out
    uint64_t monotonic_time_since_boot;
    if(get_monotonic_time_since_boot(&monotonic_time_since_boot)<0)
        return -1;
    
    // Output results
    memcpy(machine_id_out, mac_addr, 8);
    uint64_pack((char*)&machine_id_out[8], boot_time);
    uint64_pack((char*)monotonic_time_out, monotonic_time_since_boot);
    
    return 0;
}
