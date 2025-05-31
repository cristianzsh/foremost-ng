/* FOREMOST-NG
 *
 * Originally developed as FOREMOST by Jesse Kornblum, Kris Kendall, & Nick Mikus
 * Modified and extended by Cristian Souza
 */

#define TRUE            1
#define FALSE           0
#define SPECIAL_BLOCK   - 3
#define END_OF_CHAIN    - 2
#define UNUSED          - 1

#define NO_ENTRY        0
#define STORAGE         1
#define STREAM          2
#define SHORT_BLOCK     3
#define ROOT            5

#define FAT_START       0x4c
#define OUR_BLK_SIZE    512
#define DIRS_PER_BLK    4

#ifndef MIN
#define MIN(x, y)       ((x) < (y) ? (x) : (y))
#endif

#include <ctype.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct OLE_HDR {
    char        magic[8];               // 0
    char        clsid[16];              // 8
    uint16_t    uMinorVersion;          // 24
    uint16_t    uDllVersion;            // 26
    uint16_t    uByteOrder;             // 28
    uint16_t    uSectorShift;           // 30
    uint16_t    uMiniSectorShift;       // 32
    uint16_t    reserved;               // 34
    uint32_t   reserved1;               // 36
    uint32_t   reserved2;               // 40
    uint32_t   num_FAT_blocks;          // 44
    uint32_t   root_start_block;        // 48
    uint32_t   dfsignature;             // 52
    uint32_t   miniSectorCutoff;        // 56
    uint32_t   dir_flag;                // 60: first sec in mini FAT chain
    uint32_t   csectMiniFat;            // 64: number of sectors in minifat
    uint32_t   FAT_next_block;          // 68
    uint32_t   num_extra_FAT_blocks;    // 72
    // FAT block list starts here: first 109 entries
};

struct OLE_DIR {
    char            name[64];
    unsigned short  namsiz;
    char            type;
    char            bflags;             // 0 or 1
    unsigned long   prev_dirent;
    unsigned long   next_dirent;
    unsigned long   dir_dirent;
    char            clsid[16];
    unsigned long   userFlags;
    int             secs1;
    int             days1;
    int             secs2;
    int             days2;
    unsigned long   start_block;        // Starting SECT of stream
    unsigned long   size;
    short           reserved;           // Must be 0
};

struct DIRECTORY {
    char    name[64];
    int     type;
    int     level;
    int     start_block;
    int     size;
    int     next;
    int     prev;
    int     dir;
    int     s1;
    int     s2;
    int     d1;
    int     d2;
};

extern struct DIRECTORY *dirlist;
extern struct DIRECTORY *dl;

int get_dir_block(unsigned char *fd, int blknum, int buffersize);
int get_dir_info(unsigned char *src);
void extract_stream(char *fd, int blknum, int size);
void dump_header(struct OLE_HDR *h);
int dump_dirent(int which_one);

int get_block(unsigned char *fd, int blknum, unsigned char *dest,
              long long int buffersize);

int get_FAT_block(unsigned char *fd, int blknum, int *dest,
                  int buffersize);

int reorder_dirlist(struct DIRECTORY *dir, int level);

unsigned char *get_ole_block(unsigned char *fd, int blknum,
                             unsigned long long buffersize);

struct OLE_HDR *reverseBlock(struct OLE_HDR *dest, struct OLE_HDR *h);

void dump_ole_header(struct OLE_HDR *h);
void *Malloc(size_t bytes);
void die(char *fmt, void *arg);
void init_ole(void);
