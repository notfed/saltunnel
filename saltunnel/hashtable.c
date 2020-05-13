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
    
    // Hash the key to get a bucket index
    int bucket = hash(key,HASHTABLE_KEY_BYTES)%HASHTABLE_NUM_BUCKETS;
    
    // Iterate this bucket's chain
    for(hashtable_entry* e = table->e[bucket];
        e != NULL;
        e = e->chain_next)
    {
        // If we found the key, return the value
        if(memcmp(e->key,key,HASHTABLE_KEY_BYTES)==0)
            return e->value;
    }
    
    // We didn't find the key
    return NULL;
}

const unsigned char zerokey[HASHTABLE_KEY_BYTES] = {0};
int hashtable_insert(hashtable* table, unsigned char* key, unsigned char* value) {
    
    // Hash the key to get a bucket index
    int bucket = hash(key,HASHTABLE_KEY_BYTES)%HASHTABLE_NUM_BUCKETS;
    
    // Iterate this bucket's chain
    hashtable_entry** entry_prev_pp = NULL;
    for(hashtable_entry** ep = &table->e[bucket]; ;
        ep = &((*ep)->chain_next))
    {
        hashtable_entry* e = *ep;
        
        // If we reached the end of the bucket chain without finding the key, insert a new entry
        if(e==NULL) {
            
            // Create new entry
            hashtable_entry* n = malloc(sizeof(hashtable_entry));
            if(n==NULL) return -1;
            memcpy(n->key,key,HASHTABLE_KEY_BYTES);
            memcpy(n->value,value,HASHTABLE_VALUE_BYTES);
            
            // Append to chain
            *ep = n;
            n->chain_prev = entry_prev_pp ? *entry_prev_pp : NULL;
            n->chain_next = NULL;
            
            // Append to list
            n->list_prev = table->list_tail;
            n->list_next = NULL;
            
            // Append to head/tail
            if(!table->list_head) { table->list_head = n;            table->list_tail = n; }
            else                  { table->list_tail->list_next = n; table->list_tail = n; }
            
            // Delete head of list
            table->list_size++;
            if(table->list_size>HASHTABLE_NUM_ENTRIES_MAX) {
                if(hashtable_delete(table, table->list_head->key)<=0) return -1;
            }
            
            return 1;
        }
        
        // If an entry with this key already existed in this bucket, update the entry's value
        if(memcmp(e->key,key,HASHTABLE_KEY_BYTES)==0) {
            
            // Update entry
            memcpy(e->value,value,HASHTABLE_VALUE_BYTES);
            
            // Remove from list
            if(e->list_prev) e->list_prev->list_next = e->list_next;
            else                    table->list_head = e->list_next;
            if(e->list_next) e->list_next->list_prev = e->list_prev;
            else                    table->list_tail = e->list_prev;
            
            // Append to list
            e->list_prev = table->list_tail;
            e->list_next = NULL;
            
            // Append to head/tail
            if(!table->list_head) { table->list_head = e;            table->list_tail = e; }
            else                  { table->list_tail->list_next = e; table->list_tail = e; }
            
            return 1;
        }
        
        entry_prev_pp = ep;
    }
    
    // Should be impossible to get here
    return -1;
}

int hashtable_delete(hashtable* table, unsigned char* key) {
    
    // Hash the key to get a bucket index
    int bucket = hash(key,HASHTABLE_KEY_BYTES)%HASHTABLE_NUM_BUCKETS;
    
    // Iterate this bucket's chain (w/ while retaining reference to the pointers)
    for(hashtable_entry** ep = &table->e[bucket];
        *ep != NULL;
        ep = &((*ep)->chain_next))
    {
        hashtable_entry* e = *ep;
            
        // If we found the key...
        if(memcmp(e->key,key,HASHTABLE_KEY_BYTES)==0) {
            
            // Remove from list
            if(e->list_prev) e->list_prev->list_next = e->list_next;
            else                    table->list_head = e->list_next;
            if(e->list_next) e->list_next->list_prev = e->list_prev;
            else                    table->list_tail = e->list_prev;
            
            // Remove from chain
            if(e->chain_next) e->chain_next->chain_prev = e->chain_prev;
            *ep = e->chain_next; // if(e->chain_prev) e->chain_prev->chain_next = e->chain_next;
            
            // Deallocate
            free(e);
            
            // Update list size
            table->list_size--;
            
            // We successfully deleted the entry
            return 1;
        }
    }
    
    // If we didn't have any entries with this key; no need to delete anything
    return 0;
}

// clear: remove all entries from hashtable
int hashtable_clear(hashtable* table) {
    return 0; // TODO
}

// compact: if there are >max_entries entries, remove oldest entries
int hashtable_compact(hashtable* table) {
    return 0; // TODO
}
