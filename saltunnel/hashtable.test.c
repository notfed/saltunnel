#include "hashtable.test.h"
#include "hashtable.h"
#include "oops.h"
#include <stdint.h>

static void testkey(unsigned char key_out[HASHTABLE_KEY_BYTES], uint32_t val) {
    (*key_out) = val;
    memset(key_out+4,0,HASHTABLE_KEY_BYTES-4);
}
static void testvalue(unsigned char value_out[HASHTABLE_VALUE_BYTES], uint32_t val) {
    (*value_out) = val;
    memset(value_out+4,0,HASHTABLE_VALUE_BYTES-4);
}

int hashtable_test() {
    // Arrange
    hashtable table = {0};
    unsigned char key[HASHTABLE_KEY_BYTES];
    unsigned char value[HASHTABLE_VALUE_BYTES];
    
    testkey(key, 100);
    testvalue(value, 100);
    
    // Assert (Pre-Insert)
    unsigned char* pre_insert_value = hashtable_get(table, key);
    pre_insert_value==0 || oops_fatal("hashtable: pre-insert get failed");
    
    // Insert
    try(hashtable_insert(table, key, value)) || oops_fatal("hashtable: failed to insert");
    unsigned char* post_insert_value = hashtable_get(table, key);
    
    // Assert (Post-Insert)
    memcmp(post_insert_value,value,HASHTABLE_VALUE_BYTES)==0 || oops_fatal("hashtable: insert+get failed");
    
    // Delete
    hashtable_delete(table, key)==1 || oops_fatal("hashtable: failed to delete");
    
    // Assert (Post-Delete)
    unsigned char* post_delete_value = hashtable_get(table, key);
    post_delete_value==0 || oops_fatal("hashtable: post-delete get failed");
    
    return 1;
}
