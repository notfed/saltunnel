//
//  keyfile.h
//  saltunnel
//

#ifndef keyfile_h
#define keyfile_h

int keyfile_generate(const char* keyfile_path);
int keyfile_export(const char* keyfile_path);
int keyfile_import(const char* keyfile_path);
int keyfile_read(const char* keyfile_path, unsigned char key_out[32]);

#endif /* keyfile_h */
