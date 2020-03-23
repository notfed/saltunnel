//
//  hashtable.test.c
//  saltunnel
//

#include "hashtable.test.h"
#include "hashtable.h"
#include "oops.h"
#include "uint32.h"
#include <stdint.h>

static void testkey(unsigned char* key_out, uint32_t val) {
    uint32_pack((char*)key_out, val);
    memset(key_out+4,0,HASHTABLE_KEY_BYTES-4);
}
static void testvalue(unsigned char* value_out, uint32_t val) {
    uint32_pack((char*)value_out, val);
    memset(value_out+4,0,HASHTABLE_VALUE_BYTES-4);
}

void hashtable_test() {
    int stress = 10000000;
    
    // Arrange
    hashtable table = {0};
    unsigned char key[HASHTABLE_KEY_BYTES];
    unsigned char value[HASHTABLE_VALUE_BYTES];
    
    
    // Assert (Pre-Insert)
    for(int i = 1; i < stress; i+=13) {
        testkey(key, i); testvalue(value, i*3);
        unsigned char* pre_insert_value = hashtable_get(&table, key);
        pre_insert_value==0 || oops_fatal("hashtable: pre-insert get failed");
    }
    
    // Insert
    for(int i = 1; i < stress; i+=13) {
        testkey(key, i); testvalue(value,i*3);
        try(hashtable_insert(&table, key, value)) || oops_fatal("hashtable: failed to insert");
    }
    
    // Assert (Post-Insert)
    for(int i = 1; i < stress; i+=13) {
        testkey(key, i); testvalue(value,i*3);
        unsigned char* post_insert_value = hashtable_get(&table, key);
        memcmp(post_insert_value,value,HASHTABLE_VALUE_BYTES)==0 || oops_fatal("hashtable: insert+get failed");
    }
    
    // Delete
    for(int i = 1; i < stress; i+=13) {
        testkey(key, i); testvalue(value,i*3);
        hashtable_delete(&table, key)==1 || oops_fatal("hashtable: failed to delete");
    }
    
    // Assert (Post-Delete)
    for(int i = 1; i < stress; i+=13) {
        unsigned char* post_delete_value = hashtable_get(&table, key);
        post_delete_value==0 || oops_fatal("hashtable: post-delete get failed");
    }
    
    // Assert All Zero (Post-Delete)
    for(int i = 0; i < sizeof(hashtable); i++) {
        if(((char*)&table)[i]!=0) oops_fatal("hashtable: wasn't zero after deleting all");
    }
}
