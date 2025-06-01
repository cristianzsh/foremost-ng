/* FOREMOST-NG
 *
 * Originally developed as FOREMOST by Jesse Kornblum, Kris Kendall, & Nick Mikus
 * Modified and extended by Cristian Souza
 */

//#define DEBUG 1

#ifndef __FOREMOST_H
#define __FOREMOST_H

// Version information is defined in the Makefile
#define AUTHOR           "Cristian Souza"

// We use \r\n for newlines on Win32; redundant elsewhere but harmless
#define COPYRIGHT        "Original authors: Jesse Kornblum, Kris Kendall, and Nick Mikus\r\n" \
"This program is a work of the US Government. In accordance with 17 USC 105,\r\n" \
"copyright protection is not available for any work of the US Government.\r\n" \
"This is free software; see the source for copying conditions. There is NO\r\n" \
"warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.\r\n"

#define _GNU_SOURCE

// Standard headers
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <math.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// System headers
#include <sys/stat.h>
#include <sys/types.h>

// Platform-specific includes and definitions
#ifdef __LINUX
  #include <endian.h>
  #include <sys/ioctl.h>
  #include <sys/mount.h>
  #ifndef __USE_BSD
    #define __USE_BSD
  #endif
  #define uint64_t unsigned long long
#elif defined(__WIN32)
  #include <sys/param.h>
#elif defined(__MACOSX)
  #include <machine/endian.h>
  #define __U16_TYPE unsigned short
#endif

// Boolean constants
#define TRUE             1
#define FALSE            0

// Size constants
#define ONE_MEGABYTE     1048576

// Identify UNIX if not Windows
#ifndef __WIN32
  #ifndef __UNIX
    #define __UNIX
  #endif
#endif

#ifdef __UNIX
  #include <libgen.h>

  #ifndef __U16_TYPE
    #define __U16_TYPE unsigned short
  #endif

  #ifndef BYTE_ORDER
    #define BIG_ENDIAN    4321
    #define LITTLE_ENDIAN 1234
    #define BYTE_ORDER    LITTLE_ENDIAN
  #endif

  // Avoid warnings on older systems
  int fseeko(FILE *stream, off_t offset, int whence);
  off_t ftello(FILE *stream);

  // Prompts and formatting
  #define CMD_PROMPT      "$"
  #define DIR_SEPARATOR   '/'
  #define NEWLINE         "\n"
  #define LINE_LENGTH     74
  #define BLANK_LINE      "                                                                          "
#endif /* __UNIX */

#ifdef __WIN32
  // off_t must be unsigned
  #undef off_t
  #define off_t unsigned long

  #define CMD_PROMPT      "c:\\>"
  #define DIR_SEPARATOR   '\\'
  #define NEWLINE         "\r\n"
  #define LINE_LENGTH     72
  #define BLANK_LINE      "                                                                        "

  // Map file functions
  #define ftello          ftell
  #define fseeko          fseek

  #define uint32_t       unsigned long

  // Windows equivalents
  #define lstat(A,B)      stat(A,B)

  #ifdef _WIN32
    #include <direct.h>
    #define mkdir(path, mode) _mkdir(path)
    #include <limits.h>
    #define realpath(A, B) _fullpath(B, A, PATH_MAX)
  #endif

  char *my_basename(char *path);
  extern char *optarg;
  extern int optind;
  int getopt(int argc, char *const argv[], const char *optstring);
#endif /* __WIN32 */

// On non-glibc systems we have to manually set the __progname variable
extern char *__progname;

// Program defaults
#define MAX_STRING_LENGTH    1024
#define MAX_BUILTIN          50
#define COMMENT_LENGTH       64

// Mode flags
#define mode_none            0
#define mode_verbose         (1 << 1)
#define mode_quiet           (1 << 2)
#define mode_ind_blk         (1 << 3)
#define mode_quick           (1 << 4)
#define mode_write_all       (1 << 5)
#define mode_write_audit     (1 << 6)
#define mode_multi_file      (1 << 7)
#define mode_virustotal      (1 << 8)

// Search specifications
#define MAX_NEEDLES          254
#define NUM_SEARCH_SPEC_ELEMENTS 6
#define MAX_SUFFIX_LENGTH    8
#define MAX_FILE_TYPES       100
#define FOREMOST_NOEXTENSION_SUFFIX "NONE"

// Defaults
#define DEFAULT_MODE            mode_none
#define DEFAULT_CONFIG_FILE     "foremost.conf"
#define DEFAULT_OUTPUT_DIRECTORY "output"
#define AUDIT_FILE_NAME         "audit.txt"
#define FOREMOST_DIVIDER        "------------------------------------------------------------------"

// File type identifiers
#define JPEG     0
#define GIF      1
#define BMP      2
#define MPG      3
#define PDF      4
#define DOC      5
#define AVI      6
#define WMV      7
#define HTM      8
#define ZIP      9
#define MOV      10
#define XLS      11
#define PPT      12
#define WPD      13
#define CPP      14
#define OLE      15
#define GZIP     16
#define RIFF     17
#define WAV      18
#define VJPEG    19
#define SXW      20
#define SXC      21
#define SXI      22
#define CONF     23
#define PNG      24
#define RAR      25
#define EXE      26
#define ELF      27
#define REG      28
#define DOCX     29
#define XLSX     30
#define PPTX     31
#define MP4      32

// Data size units
#define KILOBYTE      1024
#define MEGABYTE      (1024 * KILOBYTE)
#define GIGABYTE      (1024 * MEGABYTE)
#define TERABYTE      (1024 * GIGABYTE)
#define PETABYTE      (1024 * TERABYTE)
#define EXABYTE       (1024 * PETABYTE)

#define UNITS_BYTES   0
#define UNITS_KILOB   1
#define UNITS_MEGAB   2
#define UNITS_GIGAB   3
#define UNITS_TERAB   4
#define UNITS_PETAB   5
#define UNITS_EXAB    6

// Search types
#define SEARCHTYPE_FORWARD       0
#define SEARCHTYPE_REVERSE       1
#define SEARCHTYPE_FORWARD_NEXT  2
#define SEARCHTYPE_ASCII         3

// Endianness
#define FOREMOST_BIG_ENDIAN      0
#define FOREMOST_LITTLE_ENDIAN   1

// Default chunk size (MB)
#define CHUNK_SIZE               100

// Global wildcard
extern char wildcard;

// State structure
typedef struct f_state {
    off_t      mode;
    char      *config_file;
    char      *input_file;
    char      *output_directory;
    char      *start_time;
    char      *invocation;
    char      *audit_file_name;
    FILE      *audit_file;
    int        audit_file_open;
    int        num_builtin;
    int        chunk_size;        /* IN MB */
    int        fileswritten;
    int        block_size;
    int        skip;
    int        time_stamp;
} f_state;

// Marker structure
typedef struct marker {
    unsigned char *value;
    int            len;
    size_t         marker_bm_table[UCHAR_MAX + 1];
} marker;

// Search specification
typedef struct s_spec {
    char      *suffix;
    int        type;
    uint64_t   max_len;
    unsigned char *header;
    unsigned int   header_len;
    size_t         header_bm_table[UCHAR_MAX + 1];
    unsigned char *footer;
    unsigned int   footer_len;
    size_t         footer_bm_table[UCHAR_MAX + 1];
    marker        markerlist[5];
    int           num_markers;
    int           searchtype;
    int           case_sen;
    int           found;
    char          comment[MAX_STRING_LENGTH];
    char          vt_label[30];
    int           written;
} s_spec;

extern s_spec search_spec[MAX_BUILTIN];

// File info
typedef struct f_info {
    char *file_name;
    off_t total_bytes;
    off_t total_megs;
    off_t bytes_read;
#ifdef __WIN32
    off_t last_read;
    off_t overflow_count;
#endif
    FILE *handle;
    int   is_stdin;
} f_info;

// Signal flag
extern int signal_caught;

// Function prototypes
int   initialize_state(f_state *s, int argc, char **argv);
void  free_state(f_state *s);
char *get_invocation(f_state *s);
char *get_start_time(f_state *s);
int   set_config_file(f_state *s, char *fn);
char *get_config_file(f_state *s);
int   set_output_directory(f_state *s, char *fn);
char *get_output_directory(f_state *s);
void  set_audit_file_open(f_state *s);
int   get_audit_file_open(f_state *s);
void  set_mode(f_state *s, off_t new_mode);
int   get_mode(f_state *s, off_t check_mode);
int   set_search_def(f_state *s, char *ft, uint64_t max_file_size);
void  get_search_def(f_state s);
void  set_input_file(f_state *s, char *filename);
void  get_input_file(f_state *s);
void  set_chunk(f_state *s, int size);
void  init_bm_table(unsigned char *needle, size_t table[UCHAR_MAX+1], size_t len, int casesensitive, int searchtype);
void  set_skip(f_state *s, int size);
void  set_block(f_state *s, int size);
#ifdef __DEBUG
void  dump_state(f_state *s);
#endif
int   open_audit_file(f_state *s);
void  audit_msg(f_state *s, char *format, ...);
int   close_audit_file(f_state *s);
int   create_output_directory(f_state *s);
int   write_to_disk(f_state *s, s_spec *needle, uint64_t len, unsigned char *buf, uint64_t t_offset);
int   create_sub_dirs(f_state *s);
void  cleanup_output(f_state *s);
int   load_config_file(f_state *s);
char *current_time(void);
off_t find_file_size(FILE *f);
char *human_readable(off_t size, char *buffer);
char *units(unsigned int c);
unsigned int chop(char *buf);
void  print_search_specs(f_state *s);
int   memwildcardcmp(const void *s1, const void *s2, size_t n, int caseSensitive);
int   charactersMatch(char a, char b, int caseSensitive);
void  printx(unsigned char *buf, int start, int end);
unsigned short htos(unsigned char s[], int endian);
unsigned int   htoi(unsigned char s[], int endian);
uint64_t       htoll(unsigned char s[], int endian);
int   displayPosition(f_state *s, f_info *i, uint64_t pos);
void  fatal_error(f_state *s, char *msg);
void  print_error(f_state *s, char *fn, char *msg);
void  print_message(f_state *s, char *format, va_list argp);
void  print_stats(f_state *s);
int   process_file(f_state *s);
int   process_stdin(f_state *s);
unsigned char *bm_search(unsigned char *needle, size_t needle_len, unsigned char *haystack, size_t haystack_len,
                          size_t table[UCHAR_MAX+1], int case_sen, int searchtype);
unsigned char *bm_search_skipn(unsigned char *needle, size_t needle_len, unsigned char *haystack, size_t haystack_len,
                                size_t table[UCHAR_MAX+1], int casesensitive, int searchtype, int start_pos);

uint16_t read_le16(unsigned char *buf);
uint32_t read_le32(unsigned char *buf);
uint64_t read_le64(unsigned char *buf);

#endif /* __FOREMOST_H */

/* BUILTIN */
unsigned char *extract_file(f_state *s, uint64_t c_offset, unsigned char *foundat, uint64_t buflen, s_spec *needle, uint64_t f_offset);
