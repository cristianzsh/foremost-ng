/* FOREMOST-NG
 *
 * Originally developed as FOREMOST by Jesse Kornblum, Kris Kendall, & Nick Mikus
 * Modified and extended by Cristian Souza
 */

#include "main.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <time.h>
#include <unistd.h>
#include <sys/types.h>

#if defined(__UNIX)
#include <sys/stat.h>
#include <fcntl.h>
#if defined(__LINUX)
#include <sys/ioctl.h>
#include <linux/fs.h>
#elif defined(__MACOSX)
#include <sys/ioctl.h>
#include <sys/disk.h>
#endif
#endif

/**
 * Remove trailing newlines ("\n", "\r") and return new length
 */
unsigned int chop(char *buf) {
    unsigned int len = strlen(buf);

    while (len > 0 && (buf[len - 1] == '\n' || buf[len - 1] == '\r')) {
        buf[--len] = '\0';
    }
    return len;
}

/**
 * Return unit string for power-of-1024 scale
 */
char *units(unsigned int c) {
    static const char *u[] = {"B", "KB", "MB", "GB", "TB", "PB", "EB"};
    return (c < sizeof(u)/sizeof(u[0])) ? (char*)u[c] : "??";
}

/**
 * Format size into buffer, e.g. "123 MB". Buffer must be at least 8 bytes.
 */
char *human_readable(off_t size, char *buffer) {
    unsigned int idx = 0;

    while (size > 1023 && idx < 6) {
        size /= 1024;
        ++idx;
    }

    snprintf(buffer, 32, "%" PRIuMAX " %s",
             (uintmax_t)size, units(idx));

    return buffer;
}

/**
 * Return current local time string without trailing newline
 */
char *current_time(void) {
    time_t now = time(NULL);
    char *ts = ctime(&now);
    chop(ts);
    return ts;
}

/**
 * Shift substring fn[new_start..] to position fn[start]
 */
void shift_string(char *fn, int start, int new_start) {
    size_t len = strlen(fn);

    if (start < 0 || new_start < start ||
        (size_t)new_start > len || (size_t)start > len) {
        return;
    }

    size_t write_pos = (size_t)start;

    for (size_t read_pos = (size_t)new_start; read_pos <= len; ++read_pos) {
        fn[write_pos++] = fn[read_pos];
    }
}
    
/**
 * Determine file size for platform variants
 */
#if defined(__UNIX)

off_t find_file_size(FILE *f) {
#if defined(__LINUX)
    int fd = fileno(f);
    struct stat sb;

    if (fstat(fd, &sb) != 0) {
        return 0;
    }

    if (S_ISREG(sb.st_mode) || S_ISDIR(sb.st_mode)) {
        return sb.st_size;
    } else if (S_ISCHR(sb.st_mode) || S_ISBLK(sb.st_mode)) {
        unsigned long sectors = 0;
        if (ioctl(fd, BLKGETSIZE, &sectors) == 0) {
            return (off_t)(sectors * 512UL);
        }
    }
    return 0;
#elif defined(__MACOSX)
    (void)f;
    return 0;
#else
    (void)f;
    return 0;
#endif
}

#elif defined(__WIN32)

off_t find_file_size(FILE *f) {
    off_t orig = ftello(f);

    if (fseeko(f, 0, SEEK_END) != 0) {
        return 0;
    }

    off_t total = ftello(f);
    fseeko(f, orig, SEEK_SET);

    return total;
}

#endif

/**
 * Print built-in search specs
 */
void print_search_specs(f_state *s) {
    printf("\nDUMPING BUILTIN SEARCH INFO\n\t");

    for (int i = 0; i < s->num_builtin; ++i) {
        printf("%s:\n\t footer_len=%d, header_len=%d, max_len=%" PRIuMAX "",
               search_spec[i].suffix,
               search_spec[i].footer_len,
               search_spec[i].header_len,
               (uintmax_t) search_spec[i].max_len);
        printf("\n\t header:\t");
        printx(search_spec[i].header, 0, search_spec[i].header_len);
        printf("\t footer:\t");
        printx(search_spec[i].footer, 0, search_spec[i].footer_len);

        for (int j = 0; j < search_spec[i].num_markers; ++j) {
            printf("\tmarker:\t");
            printx(search_spec[i].markerlist[j].value, 0,
                   search_spec[i].markerlist[j].len);
        }
    }
}

/**
 * Print extraction statistics
 */
void print_stats(f_state *s) {
    audit_msg(s, "\n%d FILES EXTRACTED\n\t", s->fileswritten);

    for (int i = 0; i < s->num_builtin; ++i) {
        if (search_spec[i].found > 0) {
            switch (search_spec[i].type) {
                case OLE:  search_spec[i].suffix = "ole"; break;
                case RIFF: search_spec[i].suffix = "rif"; break;
                case ZIP:  search_spec[i].suffix = "zip"; break;
                default: break;
            }

            audit_msg(s, "%s=%d", search_spec[i].suffix,
                      search_spec[i].found);
        }
    }
}

/**
 * Match characters with optional wildcard and case sensitivity
 */
int charactersMatch(char a, char b, int caseSensitive) {
    if (a == wildcard || a == b) {
        return 1;
    }

    if (caseSensitive) {
        return 0;

    }

    if ((unsigned char)a >= 'A' && (unsigned char)a <= 'Z') {
        a += 'a' - 'A';
    }

    if ((unsigned char)b >= 'A' && (unsigned char)b <= 'Z') {
        b += 'a' - 'A';
    }

    return a == b;
}

/**
 * Compare memory blocks with wildcard support
 */
int memwildcardcmp(const void *s1, const void *s2, size_t n, int caseSensitive) {
    const unsigned char *p1 = s1, *p2 = s2;

    for (size_t i = 0; i < n; ++i) {
        if (!charactersMatch(p1[i], p2[i], caseSensitive)) {
            return (int)p1[i] - (int)p2[i];
        }
    }

    return 0;
}

/**
 * Print bytes in hex
 */
void printx(unsigned char *buf, int start, int end) {
    for (int i = start; i < end; ++i) {
        printf("%02x ", buf[i]);
    }

    printf("\n");
}

/**
 * Reverse substring from 'from' into 'to'
 */
char* reverse_string(char *to, char *from, int start, int end) {
    int len = end - start;

    for (int i = 0; i < len; ++i) {
        to[start + i] = from[end - 1 - i];
    }

    return to;
}

/**
 * Convert network-order bytes to unsigned short
 */
unsigned short htos(unsigned char s[], int endian) {
    unsigned short val;
    memcpy(&val, s, sizeof(val));

    if ((endian == FOREMOST_BIG_ENDIAN && BYTE_ORDER == LITTLE_ENDIAN) ||
        (endian == FOREMOST_LITTLE_ENDIAN && BYTE_ORDER == BIG_ENDIAN)) {
        val = (val << 8) | (val >> 8);
    }

    return val;
}

/**
 * Convert network-order bytes to unsigned int
 */
unsigned int htoi(unsigned char s[], int endian) {
    unsigned int val;
    memcpy(&val, s, sizeof(val));

    if ((endian == FOREMOST_BIG_ENDIAN && BYTE_ORDER == LITTLE_ENDIAN) ||
        (endian == FOREMOST_LITTLE_ENDIAN && BYTE_ORDER == BIG_ENDIAN)) {
        unsigned char *b = (unsigned char*)&val;
        for (size_t i = 0; i < sizeof(val)/2; ++i) {
            unsigned char tmp = b[i];
            b[i] = b[sizeof(val)-1-i];
            b[sizeof(val)-1-i] = tmp;
        }
    }

    return val;
}

/**
 * Convert network-order bytes to uint64_t
 */
uint64_t htoll(unsigned char s[], int endian) {
    uint64_t val;
    memcpy(&val, s, sizeof(val));

    if ((endian == FOREMOST_BIG_ENDIAN && BYTE_ORDER == LITTLE_ENDIAN) ||
        (endian == FOREMOST_LITTLE_ENDIAN && BYTE_ORDER == BIG_ENDIAN)) {
        unsigned char *b = (unsigned char*)&val;
        for (size_t i = 0; i < sizeof(val)/2; ++i) {
            unsigned char tmp = b[i];
            b[i] = b[sizeof(val)-1-i];
            b[sizeof(val)-1-i] = tmp;
        }
    }

    return val;
}

/**
 * Display extraction progress
 */
int displayPosition(f_state *s, f_info *i, uint64_t pos) {
    static int last_val = -1;
    int percentDone = 0;
    int flag = 0;
    char buffer[32];
    long double total = (long double)i->total_bytes - (long double)s->skip * s->block_size;

    if (i->total_bytes > 0) {
        percentDone = (int)((pos / total) * 100.0L);
        flag = (percentDone != last_val);
        last_val = percentDone;
    } else {
        flag = 1;
    }

    if (flag) {
        int stars = percentDone / 4;
        printf("%s: |", s->input_file);
        for (int j = 0; j < stars; ++j) putchar('*');
        for (int j = stars; j < 25; ++j) putchar(' ');
        if (i->total_bytes > 0) {
            printf("| %d%% done\n", percentDone);
        } else {
            printf("| %s done\n", human_readable(pos, buffer));
        }
    }

    if (percentDone == 100) {
        last_val = -1;
    }

    return 1;
}

/**
 * Helper: read a little-endian 2-byte integer from buf.
 */
uint16_t read_le16(unsigned char *buf) {
    return htos(buf, FOREMOST_LITTLE_ENDIAN);
}

/**
 * Helper: read a little-endian 4-byte integer from buf.
 */
uint32_t read_le32(unsigned char *buf) {
    return htoi(buf, FOREMOST_LITTLE_ENDIAN);
}

/**
 * Helper: read a little-endian 8-byte integer from buf.
 */
uint64_t read_le64(unsigned char *buf) {
    return htoi(buf, FOREMOST_LITTLE_ENDIAN);
}
