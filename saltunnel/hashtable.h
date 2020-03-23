//
//  hashtable.h
//  saltunnel
//

#ifndef hashtable_h
#define hashtable_h

#define HASHTABLE_NUM_ENTRIES 65536
#define HASHTABLE_KEY_BYTES 16
#define HASHTABLE_VALUE_BYTES 8

typedef struct hashtable_entry hashtable_entry;
struct hashtable_entry {
    unsigned char key[HASHTABLE_KEY_BYTES];
    unsigned char value[HASHTABLE_VALUE_BYTES];
    hashtable_entry* chain;
};

typedef struct hashtable {
    hashtable_entry e[HASHTABLE_NUM_ENTRIES];
} hashtable;

int hashtable_insert(hashtable* table, unsigned char* key, unsigned char* value);
unsigned char* hashtable_get(hashtable* table, unsigned char* key);
int hashtable_delete(hashtable* table, unsigned char* key);

#endif /* hashtable_h */
