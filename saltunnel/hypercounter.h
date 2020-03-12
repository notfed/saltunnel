//
//  hypercounter_h
//  saltunnel
//

#ifndef hypercounter_h
#define hypercounter_h

// Gives two values:
// (1) a 16-byte value uniquely identifying this {machine,last_reboot_time}, and
// (2) an 8-byte unique, monotonically increasing number since the last reboot
int hypercounter(unsigned char machine_id_out[16],     // H(MAC address + epoch-second time)
                 unsigned char monotonic_time_out[8]); // monotonically-increasing nanoseconds-since-reboot

#endif /* hypercounter */
