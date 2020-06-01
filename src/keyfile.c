//
//  keyfile.c
//  saltunnel
//

#include "keyfile.h"
#include "oops.h"
#include "rwn.h"
#include "hex2bin.h"
#include "csprng.h"
#include "saltunnel_crypto.h"

#include <sys/resource.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

int keyfile_generate(const char* keyfile_path) {
    // Allocate
    unsigned char key[32];
    if(mlock(key, 32)<0)
        oops_warn_sys("failed to mlock key");
    
    // Generate 32-byte uniform random key
    csprng(key,32);
    
    // Save to key file
    int key_fd = open(keyfile_path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
    if(key_fd<0)
        oops_error_sys("failed to create key file");
    if(writen(key_fd, (char*)key,  32)<0)
        oops_error_sys("failed to write to key file");
    close(key_fd);
    
    // Deallocate
    memset(key,0,32);
    munlock(key, 32);
    return 0;
}

typedef struct keyfile_vars {
    unsigned char key[32];
    char key_hex[64];
    char key_hex_hyphenized[256];
} keyfile_vars;

int keyfile_export(const char* keyfile_path) {
    // Allocate pinned memory
    keyfile_vars v = {0};
    if(mlock(&v, sizeof(v))<0)
        oops_warn_sys("failed to mlock key");
    
    // Read binary key from key file
    int key_fd = open(keyfile_path, O_RDONLY);
    if(key_fd<0)
        oops_error_sys("failed to open key file");
    ssize_t bytes_read = read(key_fd, (char*)v.key,  32);
    if(bytes_read<0)
        oops_error_sys("failed to read key file");
    if(bytes_read!=32)
        oops_error("key file was not 32 bytes");
    close(key_fd);
    
    // Convert binary key to hex key
    bin2hex(v.key_hex, v.key, 32, 1);
    
    // Format hex key with hyphens
    hyphenize(v.key_hex_hyphenized, v.key_hex);
    v.key_hex_hyphenized[64+16-1] = '\n';
    
    // Output key
    const char prompt_key[] = "Key: ";
    if(writen(2, prompt_key, sizeof(prompt_key))<0)
        oops_error_sys("failed to write key to standard output");
    if(writen(1, (char*)v.key_hex_hyphenized,  64+16)<0)
        oops_error_sys("failed to write to standard output");
    
    // Calculate key hash
    unsigned char hash[32];
    crypto_hash32(hash, v.key, 32);
    char hash_hex[65];
    bin2hex(hash_hex, hash, 32, 1);
    hash_hex[sizeof(hash_hex)-1] = '\n';
    
    // Output key hash
    const char prompt_hash[] = "Checksum: ";
    if(writen(2, prompt_hash, sizeof(prompt_hash))<0)
        oops_error_sys("failed to write key to standard output");
    if(writen(2, hash_hex, sizeof(hash_hex))<0)
        oops_error_sys("failed to write to standard output");
    
    // Deallocate pinned memory
    memset(&v,0,sizeof(v));
    munlock(&v, sizeof(v));
    return 0;
}

int keyfile_import(const char* keyfile_path) {
    // Allocate
    keyfile_vars v = {0};
    if(mlock(&v, sizeof(v))<0)
        oops_warn_sys("failed to mlock key");
    
    // Prompt for the key
    if(isatty(0)) {
        const char prompt[] = "Key: ";
        if(writen(2, prompt, sizeof(prompt))<0)
            oops_error_sys("failed to write key to standard output");
    }
    
    // Read (possibly hyphenized) hex key from standard input
    ssize_t bytes_read;
    bytes_read = read(0, (char*)v.key_hex_hyphenized,  sizeof(v.key_hex_hyphenized));
    if(bytes_read<0)
        oops_error_sys("failed to read from standard input");
    
    // Strip out any non-hex characters
    int char_count = unhyphenize(v.key_hex, v.key_hex_hyphenized, (unsigned int)bytes_read);
    
    // Convert from hex to bin
    if(char_count!=64 || hex2bin(v.key, 32, v.key_hex)<0)
    { log_error("input must be a 64-character hexadecimal string"); _exit(2); }
    
    // Write to key file
    int key_fd = open(keyfile_path, O_CREAT|O_EXCL|O_RDWR, S_IRUSR|S_IWUSR);
    if(key_fd<0)
        oops_error_sys("failed to create key file");
    if(writen(key_fd, (char*)v.key,  32)<0)
        oops_error_sys("failed to write to key file");
    close(key_fd);
    
    // Calculate key hash
    unsigned char hash[32];
    crypto_hash32(hash, v.key, 32);
    char hash_hex[65];
    bin2hex(hash_hex, hash, 32, 1);
    hash_hex[sizeof(hash_hex)-1] = '\n';
    
    // Output key hash
    const char prompt_hash[] = "Checksum: ";
    if(writen(2, prompt_hash, sizeof(prompt_hash))<0)
        oops_error_sys("failed to write key to standard output");
    if(writen(2, hash_hex, sizeof(hash_hex))<0)
        oops_error_sys("failed to write to standard output");
    
    // Deallocate
    memset(&v,0,sizeof(v));
    munlock(&v, sizeof(v));
    return 0;
}

int keyfile_read(const char* keyfile_path, unsigned char* key_out) {
    if(mlock(key_out, 32)<0)
        oops_warn_sys("failed to mlock key");
    int key_fd = open(keyfile_path, O_RDONLY);
    if(key_fd<0)
        oops_error_sys("failed to open key file");
    if(readn(key_fd, (char*)key_out,  32)<0)
        oops_error_sys("failed to read key file");
    if(close(key_fd)<0) oops_error_sys("failed to close fd");
    return 0;
}
