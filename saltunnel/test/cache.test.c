//
//  cache.test.c
//  saltunnel
//

#include "cache.test.h"
#include "cache.h"
#include "oops.h"
#include "uint32.h"
#include <stdint.h>

static void gen_testkey(unsigned char* key_out, uint32_t val) {
    memset(key_out,0,CACHE_KEY_BYTES);
    uint32_pack((char*)key_out, val);
}

static void gen_testvalue(unsigned char* value_out, uint32_t val) {
    memset(value_out,0,CACHE_VALUE_BYTES);
    uint32_pack((char*)value_out, val);
}

void assert_list_has_n_entries(cache* table, int expected_n) {
    int actual_n = 0;
    for(cache_entry* e = table->list_head; e!=0; e = e->list_next)
        actual_n++;
    actual_n==expected_n || oops_fatal("cache: wrong number of members in list");
}

void cache_list_test() {
    int stress = CACHE_NUM_ENTRIES_MAX+1;
    
    // Arrange
    cache table = {0};
    unsigned char key[CACHE_KEY_BYTES] = {0};
    unsigned char value[CACHE_VALUE_BYTES] = {0};
    
    // Assert (Pre-Insert)
    assert_list_has_n_entries(&table, 0);
    for(int i = 1; i <= stress; i++) {
        gen_testkey(key, i); gen_testvalue(value, i*3);
        unsigned char* pre_insert_value = cache_get(&table, key);
        pre_insert_value==0 || oops_fatal("cache: pre-insert get failed");
    }
    
    // Insert
    for(int i = 1; i <= stress; i++) {
        gen_testkey(key, i); gen_testvalue(value,i*3);
        try(cache_insert(&table, key, value)) || oops_fatal("cache: failed to insert");
    }
    
    // Assert (Post-Insert)
    assert_list_has_n_entries(&table, CACHE_NUM_ENTRIES_MAX);
    for(int i = 1; i <= stress; i++) {
        gen_testkey(key, i); gen_testvalue(value,i*3);
        unsigned char* post_insert_value = cache_get(&table, key);
        if(i==1)
            post_insert_value == 0 || oops_fatal("cache: insert+get failed");
        else
            memcmp(post_insert_value,value,CACHE_VALUE_BYTES)==0 || oops_fatal("cache: insert+get failed");
    }
    
    // Delete
    for(int i = 1; i <= stress; i++) {
        gen_testkey(key, i); gen_testvalue(value,i*3);
        if(i==1)
            cache_delete(&table, key)==0 || oops_fatal("cache: failed to delete");
        else
            cache_delete(&table, key)==1 || oops_fatal("cache: failed to delete");
    }
    
    // Delete again (it should not fail when re-deleting)
    for(int i = 1; i <= stress; i++) {
        gen_testkey(key, i); gen_testvalue(value,i*3);
        cache_delete(&table, key)==0 || oops_fatal("cache: failed to delete");
    }
    
    // Assert (Post-Delete)
    assert_list_has_n_entries(&table, 0);
    for(int i = 1; i <= stress; i++) {
        unsigned char* post_delete_value = cache_get(&table, key);
        post_delete_value==0 || oops_fatal("cache: post-delete get failed");
    }
    
    // Assert All Zero (Post-Delete)
    for(int i = 0; i < sizeof(cache); i++) {
        if(((char*)&table)[i]!=0) oops_fatal("cache: wasn't zero after deleting all");
    }
}

void cache_delete_test() {
    int num_entries_to_insert = 262144 + 127;
    int num_entries_to_delete = 262144;
    int num_entries_to_retain = 127;
    
    // Arrange
    cache table = {0};
    unsigned char key[CACHE_KEY_BYTES] = {0};
    unsigned char value[CACHE_VALUE_BYTES] = {0};
    
    // Assert (Count == 0)
    for(int i = 1; i < num_entries_to_insert; i++) {
        gen_testkey(key, i); gen_testvalue(value, i*3);
        unsigned char* pre_insert_value = cache_get(&table, key);
        pre_insert_value==0 || oops_fatal("cache: pre-insert get failed");
    }
    
    // Insert (Count -> 262144 + 127)
    for(int i = 1; i < num_entries_to_insert; i++) {
        gen_testkey(key, i); gen_testvalue(value,i*3);
        try(cache_insert(&table, key, value)) || oops_fatal("cache: failed to insert");
    }
    
    // Assert (Count == 262144 + 127)
    for(int i = 1; i < num_entries_to_insert; i++) {
        gen_testkey(key, i); gen_testvalue(value,i*3);
        unsigned char* post_insert_value = cache_get(&table, key);
        memcmp(post_insert_value,value,CACHE_VALUE_BYTES)==0 || oops_fatal("cache: insert+get failed");
    }
    
    // Delete (Count -> 127)
    for(int i = 1; i < num_entries_to_retain; i++) {
        gen_testkey(key, i); gen_testvalue(value,i*3);
        cache_delete(&table, key)==1 || oops_fatal("cache: failed to delete");
    }
    
    // Assert (Count == 127)
    for(int i = 1; i < num_entries_to_delete; i++) {
        unsigned char* post_delete_value = cache_get(&table, key);
        post_delete_value==0 || oops_fatal("cache: post-delete get failed");
    }
//    
//    // Assert (List == [262144,262144+127))
//    cache_entry* first = table.first
//    for(int i = 1; i < num_entries_to_retain; i++) {
//
//    }
//
//    // Assert All Zero (Count == 0)
//    for(int i = 0; i < sizeof(cache); i++) {
//        if(((char*)&table)[i]!=0) oops_fatal("cache: wasn't zero after deleting all");
//    }
}


void cache_test() {
    cache_list_test();
//    cache_cache_test();
}
