//
//  cache.test.c
//  saltunnel
//

#include "cache.test.h"
#include "cache.h"
#include "oops.h"
#include "uint32.h"

#include <assert.h>
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
    assert(actual_n==expected_n);
}

void cache_test() {
    int num_entries_to_overflow = 127;
    int num_entries_to_insert = CACHE_NUM_ENTRIES_MAX + num_entries_to_overflow;
    
    // Arrange
    cache table = {0};
    unsigned char key[CACHE_KEY_BYTES] = {0};
    unsigned char value[CACHE_VALUE_BYTES] = {0};
    
    // Assert (Pre-Insert)
    assert_list_has_n_entries(&table, 0);
    for(int i = 1; i <= num_entries_to_insert; i++) {
        gen_testkey(key, i); gen_testvalue(value, i*3);
        unsigned char* pre_insert_value = cache_get(&table, key);
        assert(pre_insert_value==0);
    }
    
    // Insert
    for(int i = 1; i <= num_entries_to_insert; i++) {
        gen_testkey(key, i); gen_testvalue(value,i*3);
        assert(cache_insert(&table, key, value)==1);
    }
    
    // Assert (Post-Insert)
    assert_list_has_n_entries(&table, CACHE_NUM_ENTRIES_MAX);
    for(int i = 1; i <= num_entries_to_insert; i++) {
        gen_testkey(key, i); gen_testvalue(value,i*3);
        unsigned char* post_insert_value = cache_get(&table, key);
        if(i<=num_entries_to_overflow)
            assert(post_insert_value == 0);
        else
            assert(memcmp(post_insert_value,value,CACHE_VALUE_BYTES)==0);
    }
    
    // Delete (should get 0 return value for overflow values)
    for(int i = 1; i <= num_entries_to_insert; i++) {
        gen_testkey(key, i); gen_testvalue(value,i*3);
        if(i<=num_entries_to_overflow)
            assert(cache_delete(&table, key)==0);
        else
            assert(cache_delete(&table, key)==1);
    }
    
    // Delete again (should get 0 return value each time, now)
    for(int i = 1; i <= num_entries_to_insert; i++) {
        gen_testkey(key, i); gen_testvalue(value,i*3);
        assert(cache_delete(&table, key)==0);
    }
    
    // Assert (Post-Delete)
    assert_list_has_n_entries(&table, 0);
    for(int i = 1; i <= num_entries_to_insert; i++) {
        unsigned char* post_delete_value = cache_get(&table, key);
        assert(post_delete_value==0);
    }
    
    // Assert All Zero (Post-Delete)
    for(int i = 0; i < sizeof(cache); i++) {
        assert(((char*)&table)[i]==0);
    }
}

