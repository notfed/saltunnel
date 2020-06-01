//
//  hex2bin.c
//  saltunnel
//

#include "hex2bin.h"

static char h2b(char c) {
    return '0'<=c && c<='9' ? c - '0'      :
           'A'<=c && c<='F' ? c - 'A' + 10 :
           'a'<=c && c<='f' ? c - 'a' + 10 :
           /* else */         -1;
}

int hex2bin(unsigned char* bin,  unsigned int bin_len, const char* hex) {
    for(unsigned int i=0; i<bin_len; i++) {
        char b[2] = {h2b(hex[2*i+0]), h2b(hex[2*i+1])};
        if(b[0]<0 || b[1]<0) return -1;
        bin[i] = b[0]*16 + b[1];
    }
    return 0;
}

static char b2h(unsigned char b, int upper) {
    return b<10 ? '0'+b : (upper?'A':'a')+b-10;
}

void bin2hex(char* hex, const unsigned char* bin, unsigned int bin_len, int upper) {
    for(unsigned int i=0; i<bin_len; i++) {
        hex[2*i+0] = b2h(bin[i]>>4,   upper);
        hex[2*i+1] = b2h(bin[i]&0x0F, upper);
    }
}

void hyphenize(char key_hex_hyphenized[64+15], const char key_hex[64]) {
    int h_index = 0;
    int f_index = 0;
    for(;;) {
        for(int i=0;i<4;i++) {
            key_hex_hyphenized[f_index] = key_hex[h_index];
            h_index++;
            f_index++;
        }
        if(f_index>=64+16-1)
            break;
        key_hex_hyphenized[f_index] = '-';
        f_index++;
    }
}

int unhyphenize(char key_hex[64], const char key_hex_hyphenized[64+16], unsigned int key_hex_hyphenized_len) {
    int key_hex_count = 0;
    for(int cur_index = 0; cur_index < key_hex_hyphenized_len; cur_index++) {
        char cur_char = key_hex_hyphenized[cur_index];
        if(h2b(cur_char)!=-1) {
            key_hex[key_hex_count] = cur_char;
            key_hex_count++;
            if(key_hex_count>64)
                return -1;
        }
    }
    return key_hex_count;
}
