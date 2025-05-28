/* FOREMOST-NG
 *
 * Originally developed as FOREMOST by Jesse Kornblum, Kris Kendall, & Nick Mikus
 * Modified and extended by Cristian Souza
 */

/*
 * Local File Header (0x04034b50)
 *   - signature           4 bytes
 *   - version needed      2 bytes
 *   - general purpose flag 2 bytes
 *   - compression method  2 bytes
 *   - last mod time       2 bytes
 *   - last mod date       2 bytes
 *   - crc-32              4 bytes
 *   - compressed size     4 bytes
 *   - uncompressed size   4 bytes
 *   - filename length     2 bytes
 *   - extra field length  2 bytes
 */
struct zipLocalFileHeader {
    uint32_t signature;           /* 0x04034b50 */
    uint16_t version;             /* version needed to extract */
    uint16_t genFlag;             /* general purpose bit flag */
    int16_t  compression;         /* compression method */
    uint16_t last_mod_time;       /* last modification time */
    uint16_t last_mod_date;       /* last modification date */
    uint32_t crc;                 /* CRC-32 checksum */
    uint32_t compressed;          /* compressed size */
    uint32_t uncompressed;        /* uncompressed size */
    uint16_t filename_length;     /* length of the filename */
    uint16_t extra_length;        /* length of the extra field */
};

/*
 * Central Directory File Header (0x02014b50)
 *   - signature               4 bytes
 *   - version made by         2 bytes
 *   - version needed to extract 2 bytes
 *   - general purpose flag    2 bytes
 *   - compression method      2 bytes
 *   - last mod time           2 bytes
 *   - last mod date           2 bytes
 *   - crc-32                  4 bytes
 *   - compressed size         4 bytes
 *   - uncompressed size       4 bytes
 *   - filename length         2 bytes
 *   - extra field length      2 bytes
 *   - file comment length     2 bytes
 *   - disk number start       2 bytes
 *   - internal file attrs     2 bytes (not included)
 *   - external file attrs     4 bytes (not included)
 *   - relative offset         4 bytes (not included)
 */
struct zipCentralFileHeader {
    uint32_t signature;           /* 0x02014b50 */
    uint8_t  version_extract[2];  /* version needed to extract */
    uint8_t  version_madeby[2];   /* version made by */
    uint16_t genFlag;             /* general purpose bit flag */
    uint16_t compression;         /* compression method */
    uint16_t last_mod_time;       /* last modification time */
    uint16_t last_mod_date;       /* last modification date */
    uint32_t crc;                 /* CRC-32 checksum */
    uint32_t compressed;          /* compressed size */
    uint32_t uncompressed;        /* uncompressed size */
    uint16_t filename_length;     /* length of the filename */
    uint16_t extra_length;        /* length of the extra field */
    uint16_t filecomment_length;  /* length of the comment */
    uint16_t disk_number_start;   /* disk number where central dir starts */
};

/*
 * End of Central Directory Record (0x06054b50)
 *   - signature               4 bytes
 *   - number of this disk     2 bytes
 *   - disk with central dir   2 bytes
 *   - entries on this disk    2 bytes
 *   - total entries           2 bytes
 *   - size of central dir     4 bytes
 *   - offset of central dir   4 bytes
 *   - comment length          2 bytes
 */
struct zipEndCentralFileHeader {
    uint32_t signature;           /* 0x06054b50 */
    uint16_t disk_number;         /* number of this disk */
    uint16_t start_disk;          /* disk with central directory */
    uint16_t entries_this;        /* entries on this disk */
    uint16_t entries_total;       /* total entries in central dir */
    uint32_t size_central;        /* size of central directory */
    uint32_t offset;              /* offset of start of central dir */
    uint16_t comment_length;      /* length of the zip file comment */
};

#include <stdio.h>

/*
 * Debug print routine for local and central headers
 */
void print_zip(
    const struct zipLocalFileHeader   *local,
    const struct zipCentralFileHeader *central
) {
    printf("\nLocal Header Data:\n");
    printf("  genFlag       = %u\n"
           "  compressed    = %lu bytes\n"
           "  uncompressed  = %lu bytes\n"
           "  compression   = %d\n"
           "  filename_len  = %u\n"
           "  extra_len     = %u\n",
           (unsigned)local->genFlag,
           (unsigned long)local->compressed,
           (unsigned long)local->uncompressed,
           local->compression,
           (unsigned)local->filename_length,
           (unsigned)local->extra_length
    );

    printf("\nCentral Header Data:\n");
    printf("  genFlag       = %u\n"
           "  compressed    = %lu bytes\n"
           "  uncompressed  = %lu bytes\n"
           "  compression   = %u\n"
           "  verMadeBy     = %02x%02x\n",
           (unsigned)central->genFlag,
           (unsigned long)central->compressed,
           (unsigned long)central->uncompressed,
           (unsigned)central->compression,
           central->version_madeby[0],
           central->version_madeby[1]
    );
}
