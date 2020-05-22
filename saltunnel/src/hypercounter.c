//
//  hypercounter.c
//  saltunnel
//

#include "hypercounter.h"
#include "uint64.h"
#include "rwn.h"
#include "oops.h"

#include <sodium.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <time.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <ifaddrs.h>
#include <errno.h>
#include <stdio.h>
#include <time.h>
#if defined(__APPLE__)
#include <sys/sysctl.h>
#include <net/if_dl.h>
#include <mach/clock.h>
#include <mach/mach.h>
#endif

int hypercounter_init() {
    unsigned char machine_boot_id_out[16];
    unsigned char monotonic_time_out[8];
    return hypercounter(machine_boot_id_out, monotonic_time_out);
}

#ifdef KERN_BOOTTIME
// Get when this machine last booted (using KERN_BOOTTIME) (OS X)
uint64_t get_boot_time() {
    struct timeval boottime;
    int mib[2] = {CTL_KERN, KERN_BOOTTIME};
    size_t size = sizeof(boottime);
    int rc = sysctl(mib, 2, &boottime, &size, NULL, 0);
    if (rc != 0) 
        return 0;
    uint64_t result = (uint64_t)boottime.tv_sec * 1000000 + (uint64_t)boottime.tv_usec;
    return result;
}
#else
// Get when this machine last booted (using /proc/stat[btime]) (Linux)
uint64_t get_boot_time() {
   char token[1024];
   FILE* fp = fopen("/proc/stat", "r");
   if(fp==0)
       return 0;
   while(fscanf(fp, "%1023s", token)>0) {
       if(strcmp("btime",token)==0) {
           unsigned int btime;
           int r = fscanf(fp, "%u", &btime);
           fclose(fp);
           if(r==1)
             return btime;
           else
             return 0;
       }
   }
   fclose(fp);
   return 0;
}
#endif

// Get monotonic time since last boot
static int get_monotonic_time_since_boot(uint64_t* monotonic_time_out) {
    struct timespec time;
    if(clock_gettime(CLOCK_REALTIME, &time)<0)
        return -1;
    *monotonic_time_out = (uint64_t)time.tv_sec * 1000000 + (uint64_t)time.tv_nsec;
    return 0;
}

#if defined(__APPLE__)
// Get MAC address of (any) network interface (Used if machine-id not available) (OS X)
int get_mac_address(unsigned char mac_addr[6]) {
    struct ifaddrs* iflist;
    const unsigned char mac_addr_zero[6] = {0};
    unsigned char mac_addr_tmp[6];
    int found = -1;

    // Loop through each network interface
    if (getifaddrs(&iflist) == 0) {
        for (struct ifaddrs* cur = iflist; cur; cur = cur->ifa_next) {

            // Filter for ipv4 devices
            if (cur->ifa_addr && cur->ifa_addr->sa_family == AF_LINK) {
                struct sockaddr_dl* sdl = (struct sockaddr_dl*)cur->ifa_addr;

                // Filter for 6-byte MAC addresses
                if(sdl->sdl_alen==6) {
                    memcpy(mac_addr_tmp, LLADDR(sdl), 6);

                    // Filter for non-zero MAC addresses
                    if(memcmp(mac_addr_zero, mac_addr_tmp, 6)!=0) {
                        memcpy(mac_addr, mac_addr_tmp, 6);
                        found = 1;
                        break;
                    }
                }
            }
        }

        freeifaddrs(iflist);
    }
    return found;
}
#else
// Get MAC address of (any) network interface (Used if machine-id not available) (Linux)
int get_mac_address(unsigned char mac_address[6]) {
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
#endif

// Get the unique id for this machine (from the MAC address of eth0)
static int get_machine_id_from_mac_address(unsigned char machine_id_out[16])
{
    memset(machine_id_out, 0, 16);
    return get_mac_address(machine_id_out);
}

// Get the unique id for this machine (from a 32-byte hexadecimal file)
static int get_machine_id_from_file(unsigned char machine_id_out[16], const char* file_name)
{
    // Open file (e.g., /etc/machine-id)
    int machine_id_fd = open(file_name, O_RDONLY);
    if(machine_id_fd<0) 
        return -1;

    // Read 32 bytes; should be hexadecimal text
    char machine_id_hex[32];
    if(readn(machine_id_fd, machine_id_hex, 32)!=32) 
        return -1;

    // Convert hexadecimal text to binary
    if(sodium_hex2bin(machine_id_out, 16,
                      machine_id_hex, 32,
                      NULL, NULL, NULL)<0) return -1;

    return 0;
}

// Get the unique id for this machine
static int get_machine_id(unsigned char machine_id_out[16])
{
    static int did_cache_machine_id = 0;
    static unsigned char cached_machine_id[16];
    if(!did_cache_machine_id) {
        if(get_machine_id_from_file(cached_machine_id, "~/.saltunnel/machine-id")<0)
          if(get_machine_id_from_file(cached_machine_id, "/etc/machine-id")<0)
            if(get_machine_id_from_mac_address(cached_machine_id)<0)
                oops_error("failed to find a unique machine-id (tried '~/.saltunnel/machine-id', '/etc/machine-id', and MAC address)");
        did_cache_machine_id = 1;
    }
    memcpy(machine_id_out, cached_machine_id, 16);
    return 0;
}

int hypercounter(unsigned char machine_boot_id_out[16], unsigned char monotonic_time_out[8]) {
    
    // Get the unique id for this machine
    unsigned char machine_id_and_boot_time[32];
    if(get_machine_id(&machine_id_and_boot_time[0])<0)
        return -1;

    // Get when this machine last booted
    uint64_t boot_time = get_boot_time();
    if(boot_time==0)
        return -1;
    uint64_pack((char*)&machine_id_and_boot_time[16], boot_time);

    // Hash(machine_id, boot_time) to get machine_boot_id
    if(crypto_generichash(machine_boot_id_out, 16,
                   machine_id_and_boot_time, 32,
                   NULL, 0)<0) 
    { return -1; }

    // Get monotonic time since last boot
    uint64_t monotonic_time_since_boot;
    if(get_monotonic_time_since_boot(&monotonic_time_since_boot)<0)
        return -1;
    uint64_pack((char*)monotonic_time_out, monotonic_time_since_boot);
    
    return 0;
}
