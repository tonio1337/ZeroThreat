#define _GNU_SOURCE
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <dirent.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>

typedef unsigned char int8;
typedef unsigned short int int16;
typedef unsigned int int32;
typedef unsigned long long int int64;

#define Blocksize 50000

#define $1 (int8 *)
#define $2 (int16)
#define $4 (int32)
#define $8(int64)
#define $c(char)
#define $i(int)

typedef int8 Dir[64];
typedef int8 File[32];

enum e_filetype {
    file = 1,
    dir = 2,
    other = 3
};

typedef enum e_filetype Filetype;

struct a_database {
    Dir dir;       // Changed from Dir* to Dir
    File file;     // Changed from File* to File
    Filetype type; // Added this field to store the type (file, dir, or other)
};

typedef struct a_database Entry;

struct s_database {
    Entry *entries;
    int32 cap;
    int32 size;
};

typedef struct s_database Database;
typedef bool (*function)(Entry);

#define linux_dirent dirent

Database *filter(Database*, function);
Database *mkdatabase(void);
bool adddir(Database*, int8*);
void addtodb(Database*, Entry);
void deletedb(Database*);
void showdb(Database*);

int main(int, char**);