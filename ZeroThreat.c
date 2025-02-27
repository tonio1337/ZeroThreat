#include "Zerothreat.h"
#include <dirent.h>

void destroydb(Database *db);

bool onedot(const char *filename);
bool twodots(const char *filename);

bool is_malicious(const char *filename);
bool is_malicious_content(const char *filepath);  

bool testfunction(Entry e) {
    return(e.type == file);
}

Database *filter(Database *input, function f) {
    int32 n;
    Database *output;
    Entry *p;
    bool predicate;

    output = mkdatabase();
    for(n = 0; n < input->size; n++) {
        p = &input->entries[n];
        predicate = f(*p);
        if (predicate)
            addtodb(output, *p);
    }
    destroydb(input);
    return output;
}

Database *mkdatabase() {
    Database *db;
    Entry *p;
    int32 size;

    size = sizeof(struct s_database);
    db = (Database *)malloc(size);
    assert(db);
    memset(db, 0, size);
    db->size = 0;
    db->cap = Blocksize;
    size = Blocksize * sizeof(Entry);
    p = (Entry *)malloc(size);
    assert(p);
    memset(p, 0, size);
    db->entries = p;

    return db;
}

void destroydb(Database *db) {
    db->cap = 0;
    db->size = 0;
    free(db->entries);
    free(db);
    return;
}

void showdb(Database *db) {
    int32 n;
    printf("cap:\t%d\nsize:\t%d\n", db->cap, db->size);

    for(n = 0; n < db->size; n++)
        printf("%s/%s%c\n", db->entries[n].dir, db->entries[n].file,
            (db->entries[n].type == dir) ? '/' : '\0');
    return;
}

void addtodb(Database *db, Entry e) {
    int32 size, cap, ix;
    if (db->size == db->cap) {
        cap = db->cap + Blocksize;
        size = cap * sizeof(Entry);
        db->entries = realloc(db->entries, size);
        assert(db->entries);
        db->cap = cap;
    }

    ix = db->size;
    memcpy(&db->entries[ix], &e, sizeof(Entry));
    db->size++;
    return;
}

bool adddir(Database *db, int8 *path) {
    Entry e;
    DIR *dirp;
    struct dirent *entry;

    dirp = opendir((char *)path);
    if (!dirp)
        return false;

    while ((entry = readdir(dirp)) != NULL) {
        memset(&e, 0, sizeof(Entry));

        if (onedot(entry->d_name) || twodots(entry->d_name))
            continue;

        if (entry->d_type & DT_REG) {
            e.type = file;
            strncpy((char *)e.dir, (char *)path, 63);
            strncpy((char *)e.file, entry->d_name, 31);

            
            char filepath[128];
            snprintf(filepath, sizeof(filepath), "%s/%s", (char *)path, entry->d_name);

            
            if (is_malicious(entry->d_name) || is_malicious_content(filepath)) {
                printf("[WARNING] Potential Malicious file detected: %s/%s\n", (char *)path, entry->d_name);
            }

            addtodb(db, e);
        } else if (entry->d_type & DT_DIR) {
            e.type = dir;
            strncpy((char *)e.dir, (char *)path, 63);
            strncpy((char *)e.file, entry->d_name, 31);
            addtodb(db, e);

            char tmp[64];
            memset(tmp, 0, 64);
            snprintf(tmp, 63, "%s/%s", (char *)path, (char *)e.file);
            adddir(db, (int8 *)tmp);
        }
    }

    closedir(dirp);
    return true;
}

bool onedot(const char *filename) {
    return strcmp(filename, ".") == 0;
}

bool twodots(const char *filename) {
    return strcmp(filename, "..") == 0;
}

bool is_malicious(const char *filename) {
    const char *malicious_extensions[] = {
        ".scr", ".vbs", ".rtf", ".msi", ".com", ".cmd", ".bat", ".scr", ".vbs", NULL
    };

    const char *malicious_strings[] = {
        "malware", "virus", "trojan", "ransomware", "worm", NULL
    };

    for (int i = 0; malicious_extensions[i] != NULL; i++) {
        if (strstr(filename, malicious_extensions[i]) != NULL) {
            return true;
        }
    }

    for (int i = 0; malicious_strings[i] != NULL; i++) {
        if (strstr(filename, malicious_strings[i]) != NULL) {
            return true;
        }
    }

    return false;
}


bool is_malicious_content(const char *filepath) {
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        perror("Failed to open file");
        return false;
    }

    
    const char *malicious_patterns[] = {
        "\x4D\x5A", 
        "\x50\x4B\x03\x04",  
        NULL
    };

    char buffer[1024];
    size_t bytes_read = fread(buffer, 1, sizeof(buffer), file);
    fclose(file);

    if (bytes_read > 0) {
        for (int i = 0; malicious_patterns[i] != NULL; i++) {
            if (memmem(buffer, bytes_read, malicious_patterns[i], strlen(malicious_patterns[i])) != NULL) {
                return true;
            }
        }
    }

    return false;
}

int main(int argc, char *argv[]) {
    Database *db, *db2;
    assert(argc > 1);
    db = mkdatabase();
    adddir(db, (int8 *)argv[1]);
    db2 = filter(db, &testfunction);
    showdb(db2);
    destroydb(db2);

    return 0;
}