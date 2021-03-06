//
//  hypercounter.h
//  saltunnel
//
//  A hypercounter is a {machine,time} identifier. The motivation is to enable
//  replay-attack prevention: each hypercounter should always increase in
//  time for a given machine.
//

#ifndef hypercounter_h
#define hypercounter_h

// If the app calls hypercounter from multiple threads, call this at application-startup time.
int hypercounter_init(void);

// Gives two values:
// (1) a 16-byte value uniquely identifying this {machine,last_reboot_time}, and
// (2) an 8-byte unique, monotonically increasing number since the last reboot
int hypercounter(unsigned char machine_id_out[16],     // H(MAC address + last-reboot time)
                 unsigned char monotonic_time_out[8]); // monotonically-increasing nanoseconds-since-reboot

#endif /* hypercounter_h */
