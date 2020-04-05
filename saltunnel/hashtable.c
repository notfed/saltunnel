//
//  hashtable.c
//  saltunnel
//

#include "hashtable.h"
#include <string.h>
#include <stdlib.h>

static unsigned long long hash(unsigned char* str, unsigned int len)
{
    unsigned long long hash = 5381;
    int c;
    while(len>0) {
        len--;
        c = *str++;
        hash = ((hash << 5) + hash) + c; /* hash * 33 + c */
    }
    return hash;
}

unsigned char* hashtable_get(hashtable* table, unsigned char* key) {
    
    // Start at a slot, iterate its chain
    int slot = hash(key,HASHTABLE_KEY_BYTES)%HASHTABLE_NUM_ENTRIES;
    for(hashtable_entry* maybe_entry = &table->e[slot];
        maybe_entry != NULL;
        maybe_entry = maybe_entry->chain)
    {
        // If we found the key, return the value
        if(memcmp(maybe_entry->key,key,HASHTABLE_KEY_BYTES)==0)
            return maybe_entry->value;
    }
    
    // We didn't find the key
    return NULL;
}

const unsigned char zerokey[HASHTABLE_KEY_BYTES] = {0};
int hashtable_insert(hashtable* table, unsigned char* key, unsigned char* value) {
    
    // Start at a slot, iterate its chain
    int slot = hash(key,HASHTABLE_KEY_BYTES)%HASHTABLE_NUM_ENTRIES;
    for(hashtable_entry* maybe_entry = &table->e[slot];
        maybe_entry != NULL;
        maybe_entry = maybe_entry->chain)
    {
        // If we found the key, update the value
        if(memcmp(maybe_entry->key,key,HASHTABLE_KEY_BYTES)==0) {
            memcpy(maybe_entry->value,value,HASHTABLE_KEY_BYTES);
            return 1;
        }
        
        // If we didn't find the key, and primary slot is free, insert the entry
        if(memcmp(maybe_entry->key,zerokey,HASHTABLE_KEY_BYTES)==0) {
            memcpy(maybe_entry->key,key,HASHTABLE_KEY_BYTES);
            memcpy(maybe_entry->value,value,HASHTABLE_VALUE_BYTES);
            memset(&maybe_entry->chain, 0, sizeof(void*));
            return 1;
        }
        
        // If we didn't find the key, and primary slot is taken, insert a new entry into the chain
        if(maybe_entry->chain==0) {
            hashtable_entry* n = malloc(sizeof(hashtable_entry));
            if(n==NULL) return -1;
            memcpy(n->key,key,HASHTABLE_KEY_BYTES);
            memcpy(n->value,value,HASHTABLE_VALUE_BYTES);
            memset(&n->chain, 0, sizeof(void*));
            maybe_entry->chain = n;
            return 1;
        }
    }
    return -1;
}

int hashtable_delete(hashtable* table, unsigned char* key) {
    
    hashtable_entry* prev_entry = 0;
    
    // Start at a slot, iterate its chain
    int slot = hash(key,HASHTABLE_KEY_BYTES)%HASHTABLE_NUM_ENTRIES;
    for(hashtable_entry* maybe_entry = &table->e[slot];
        maybe_entry != NULL;
        maybe_entry = maybe_entry->chain)
    {
        // If we found the key...
        if(memcmp(maybe_entry->key,key,HASHTABLE_KEY_BYTES)==0) {

            hashtable_entry* next_entry = maybe_entry->chain;
            
            // If this is a non-primary entry, re-point prev to next and deallocate cur
            if(prev_entry) {
                prev_entry->chain = next_entry;
                memset(maybe_entry, 0, sizeof(hashtable_entry));
                free(maybe_entry);
                return 1;
            }
            // If this is the primary entry, and there's a next entry, copy next to cur and deallocate next
            else if(next_entry) {
                memcpy(maybe_entry, next_entry, sizeof(hashtable_entry));
                free(next_entry);
                return 1;
            }
            // If this is the primary entry, and there's no next entry, simply clear it out
            else {
                memset(maybe_entry, 0, sizeof(hashtable_entry));
                return 1;
            }
        }
        
        // If we didn't find the key, can't delete it
        if(maybe_entry->chain==0) {
            return 0;
        }
        
        prev_entry = maybe_entry;
    }
    
    return 1;
}

// clear: remove all entries from hashtable
int hashtable_clear(hashtable* table) {
    return 0; // TODO
}

// compact: if there are >max_entries entries, remove oldest entries
int hashtable_compact(hashtable* table) {
    return 0; // TODO
}
