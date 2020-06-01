//
//  hex2bin.h
//  saltunnel
//
//  Convert hex strings to byte arrays and vice versa.
//

#ifndef hex2bin_h
#define hex2bin_h

int hex2bin(unsigned char* bin, unsigned int bin_len, const char* hex);
void bin2hex(char* hex, const unsigned char* bin, unsigned int bin_len, int upper);

void hyphenize(char key_hex_hyphenized[64+16], const char key_hex[64]);
int unhyphenize(char key_hex[64], const char* key_hex_hyphenized, unsigned int key_hex_hyphenized_len);

#endif /* hex2bin_h */
