/* FOREMOST-NG
 *
 * Originally developed as FOREMOST by Jesse Kornblum, Kris Kendall, & Nick Mikus
 * Modified and extended by Cristian Souza
 */

#include "main.h"
#include "ansi_colors.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>

/* Print animated sliding progress bar */
void print_sliding_bar() {
    static int frame = 0;
    const char *templates[] = {
        "[=     ]", "[ =    ]", "[  =   ]", "[   =  ]", "[    = ]", "[     =]",
        "[    = ]", "[   =  ]", "[  =   ]", "[ =    ]"
    };
    fprintf(stderr, "\r" ANSI_YELLOW "%s" ANSI_RESET, templates[frame]);
    fflush(stderr);
    frame = (frame + 1) % (sizeof(templates) / sizeof(templates[0]));
}

/* Handle user interrupt: close handle, clean up, free and exit */
int user_interrupt(f_state *s, f_info *i) {
    audit_msg(s, "Interrupt received at %s", current_time());
    fclose(i->handle);
    cleanup_output(s);
    free(s);
    free(i);
    exit(-1);
    return FALSE;
}

/* Read length bytes from offset into newly malloc'd buffer */
unsigned char *read_from_disk(uint64_t offset, f_info *i, uint64_t length) {
    unsigned char *newbuf = malloc(length);
    if (!newbuf) {
        fprintf(stderr, "Ran out of memory in read_from_disk()\n");
        exit(1);
    }

    //Seek to the requested file offset
    fseeko(i->handle, offset, SEEK_SET);
    if (fread(newbuf, 1, length, i->handle) != length) {
        free(newbuf);
        return NULL;
    }
    return newbuf;
}

/* Perform modified Boyer-Moore search with wildcards and custom start */
unsigned char *bm_search_skipn(
    unsigned char *needle, size_t needle_len,
    unsigned char *haystack, size_t haystack_len,
    size_t table[UCHAR_MAX + 1],
    int casesensitive, int searchtype, int start_pos
) {
    size_t shift, pos = start_pos;
    unsigned char *here;

    if (needle_len == 0)
        return haystack;

    if (searchtype == SEARCHTYPE_FORWARD || searchtype == SEARCHTYPE_FORWARD_NEXT) {
        // Forward search using bad-character shifts
        while (pos < haystack_len) {
            // Jump ahead by shift value
            while (pos < haystack_len &&
                   (shift = table[(unsigned char)haystack[pos]]) > 0) {
                pos += shift;
            }
            if (shift == 0) {
                here = &haystack[pos - needle_len + 1];
                // Compare allowing wildcards
                if (memwildcardcmp(needle, here, needle_len, casesensitive) == 0) {
                    return here;
                }
                pos++;
            }
        }
        return NULL;
    }
    else if (searchtype == SEARCHTYPE_REVERSE) {
        // Reverse search scanning from buffer end
        while (pos < haystack_len) {
            while (pos < haystack_len &&
                   (shift = table[(unsigned char)haystack[haystack_len - pos - 1]]) > 0) {
                pos += shift;
            }
            if (shift == 0) {
                here = &haystack[haystack_len - pos - 1];
                if (memwildcardcmp(needle, here, needle_len, casesensitive) == 0) {
                    return here;
                }
                pos++;
            }
        }
        return NULL;
    }
    return NULL;
}

/* Wrapper: start Boyer-Moore at needle_len - 1 */
unsigned char *bm_search(
    unsigned char *needle, size_t needle_len,
    unsigned char *haystack, size_t haystack_len,
    size_t table[UCHAR_MAX + 1],
    int case_sen, int searchtype
) {
    return bm_search_skipn(
        needle, needle_len, haystack, haystack_len,
        table, case_sen, searchtype, needle_len - 1
    );
}

/* Set up reading stream: skip bytes and log sizes */
void setup_stream(f_state *s, f_info *i) {
    char buffer[MAX_STRING_LENGTH];
    uint64_t skip = (uint64_t)s->skip * s->block_size;

#ifdef DEBUG
    printf("s->skip=%d s->block_size=%d total=%llu\n",
           s->skip, s->block_size, skip);
#endif

    i->bytes_read = 0;
    i->total_megs = i->total_bytes / ONE_MEGABYTE;

    if (i->total_bytes) {
        audit_msg(s, "Length: %s (%llu bytes)",
                  human_readable(i->total_bytes, buffer),
                  i->total_bytes);
    } else {
        audit_msg(s, "Length: Unknown");
    }

    if (s->skip) {
        audit_msg(s, "Skipping: %s (%llu bytes)",
                  human_readable(skip, buffer), skip);
        fseeko(i->handle, skip, SEEK_SET);
        if (i->total_bytes)
            i->total_bytes -= skip;
    }

    audit_msg(s, " ");

#ifdef __WIN32
    // Reset Windows-specific counters
    i->last_read = 0;
    i->overflow_count = 0;
#endif
}

/* Print column headers for audit output */
void audit_layout(f_state *s) {
    char name_col[32];
    snprintf(name_col, sizeof(name_col), "Name (bs=%d)", s->block_size);

    audit_msg(s,
        "%4s  %-20s %10s %12s  %-24s  %-15s",
        "ID", name_col, "Size", "Offset", "Comment", "VT"
    );
}

/* Dump indirect block values for debugging */
void dumpInd(unsigned char *ind, int bs) {
    int i = 0;
    printf("\n/*******************************/\n");
    while (bs > 0) {
        if (i % 10 == 0) printf("\n");
        // Print each 4-byte little-endian word
        printf("%4u ", htoi(ind, FOREMOST_LITTLE_ENDIAN));
        bs -= 4;
        ind += 4;
        i++;
    }
    printf("\n/*******************************/\n");
}

/* Check if buffer at foundat represents a valid indirect block */
int ind_block(unsigned char *foundat, uint64_t buflen, int bs) {
    unsigned char *temp = foundat;
    int jump = 12 * bs;                         /* Offset to pointers */
    unsigned int block, block2, dif;
    int i = 0;
    unsigned int numbers = (bs / 4) - 1;

    // Ensure buffer contains at least two pointers
    if (buflen < (uint64_t)jump + 16)
        return FALSE;

    // Check sequential pointer increments
    while (i < (int)numbers) {
        block = htoi(&temp[jump + i*4], FOREMOST_LITTLE_ENDIAN);
        if (block == 0) break;
        i++;
        block2 = htoi(&temp[jump + i*4], FOREMOST_LITTLE_ENDIAN);
        if (block2 == 0) break;
        dif = block2 - block;
        if (dif != 1) return FALSE;
    }
    if (i == 0) return FALSE;

    // Verify remaining pointers are zero
    for (i = i + 1; i < (int)numbers; i++) {
        if (htoi(&temp[jump + i*4], FOREMOST_LITTLE_ENDIAN) != 0)
            return FALSE;
    }
    return TRUE;
}

/* Search a chunk for all file types and extract matches */
int search_chunk(
    f_state *s, unsigned char *buf, f_info *i,
    uint64_t chunk_size, uint64_t f_offset
) {
    uint64_t c_offset, current_buflen = chunk_size;
    unsigned char *foundat, *header_pos = NULL;
    unsigned char *newbuf = NULL, *ind_ptr = NULL;
    int tryBS[3] = {4096, 1024, 512}, bs, rem, x, found_ind;
    unsigned char *extractbuf = NULL;
    uint64_t file_size;
    s_spec *needle;
    off_t saveme;

    for (int j = 0; j < s->num_builtin; j++) {
        needle = &search_spec[j];
        foundat = buf;
        current_buflen = chunk_size;

#ifdef DEBUG
        printf("    SEARCHING FOR %s\n", needle->suffix);
#endif

        while (foundat) {
            needle->written = FALSE;
            found_ind = FALSE;
            memset(needle->comment, 0, COMMENT_LENGTH - 1);

            // Avoid buffer overflow on pointer arithmetic
            if ((uint64_t)(foundat - buf) >= chunk_size) {
#ifdef DEBUG
                printf("Avoided segfault in search_chunk()\n");
#endif
                break;
            }
            current_buflen = chunk_size - (foundat - buf);

            // Handle SIGINT/SIGTERM
            if (signal_caught == SIGTERM || signal_caught == SIGINT) {
                user_interrupt(s, i);
                signal_caught = 0;
            }

            if (get_mode(s, mode_quick)) {
                // Quick block-aligned search
                rem = (foundat - buf) % s->block_size;
                if (rem) foundat += (s->block_size - rem);

                // Compare header at block boundary
                if (memwildcardcmp(
                        needle->header, foundat,
                        needle->header_len, needle->case_sen) != 0) {
                    if (current_buflen > (uint64_t)s->block_size) {
                        foundat += s->block_size;
                        continue;
                    } else {
                        break;
                    }
                }
                header_pos = foundat;
            } else {
                // Standard forward search
                foundat = bm_search(
                    needle->header, needle->header_len,
                    foundat, current_buflen,
                    needle->header_bm_table,
                    needle->case_sen,
                    SEARCHTYPE_FORWARD
                );
                header_pos = foundat;
            }

            if (!foundat) break;
            current_buflen = chunk_size - (foundat - buf);

            // Indirect-block detection and buffer shift
            if (get_mode(s, mode_ind_blk)) {
                for (x = 0; x < 3; x++) {
                    bs = tryBS[x];
                    if (ind_block(foundat, current_buflen, bs)) {
                        if (get_mode(s, mode_verbose)) {
                            sprintf(needle->comment, " (IND BLK bs=%d)", bs);
                        }
                        if (current_buflen > (uint64_t)(13*bs)) {
                            // Shift buffer to remove indirect block
                            memmove(foundat + 12*bs,
                                    foundat + 13*bs,
                                    current_buflen - 13*bs);
                            found_ind = TRUE;
                            ind_ptr = foundat + 12*bs;
                            chunk_size -= bs;
                            current_buflen -= bs;
                            break;
                        }
                    }
                }
            }

            c_offset = foundat - buf;
            // Extract file and update foundat
            foundat = extract_file(
                s, c_offset, foundat,
                current_buflen, needle, f_offset
            );

            // Write header dump if in write-all mode
            if (get_mode(s, mode_write_all) && !needle->written) {
                file_size = (current_buflen >= needle->max_len)
                    ? needle->max_len : current_buflen;
                sprintf(needle->comment, " (Header dump)");
                extractbuf = malloc(file_size);
                memcpy(extractbuf, header_pos, file_size);
                write_to_disk(s, needle, file_size, extractbuf, c_offset + f_offset);
                free(extractbuf);
            }
            // Bridge across chunk boundary if needed
            else if (!foundat && current_buflen < needle->max_len) {
#ifdef DEBUG
                printf("    Bridge the gap\n");
#endif
                saveme = ftello(i->handle);
                newbuf = read_from_disk(c_offset + f_offset, i, needle->max_len);
                if (!newbuf) break;
                extract_file(s, c_offset, newbuf, needle->max_len, needle, f_offset);
                fseeko(i->handle, saveme, SEEK_SET);
                free(newbuf);
                break;
            }

            // Restore buffer if we shifted an indirect block
            if (found_ind) {
#ifdef DEBUG
                printf("Replacing the ind block\n");
#endif
                memmove(ind_ptr + bs, ind_ptr, current_buflen - 13*bs);
                memset(ind_ptr, 0, bs);
                chunk_size += bs;
                memset(needle->comment, 0, COMMENT_LENGTH - 1);
            }
        }
    }
    return TRUE;
}

/* Read file in chunks and process each chunk */
int search_stream(f_state *s, f_info *i) {
    uint64_t bytesread = 0, f_offset = 0;
    uint64_t chunk_size = (uint64_t)s->chunk_size * MEGABYTE;
    unsigned char *buf = malloc(chunk_size);

    setup_stream(s, i);
    audit_layout(s);

#ifdef DEBUG
    printf("\n     READING THE FILE INTO MEMORY\n");
#endif
    while ((bytesread = fread(buf, 1, chunk_size, i->handle)) > 0) {
        if (signal_caught == SIGTERM || signal_caught == SIGINT) {
            user_interrupt(s, i);
            signal_caught = 0;
        }
#ifdef DEBUG
        printf("\n     bytes_read:=%llu\n", bytesread);
#endif
        search_chunk(s, buf, i, bytesread, f_offset);
        f_offset += bytesread;
        if (!get_mode(s, mode_quiet) && !get_mode(s, mode_verbose)) {
            print_sliding_bar();
        }
    }

    if (!get_mode(s, mode_quiet)) {
        fprintf(stderr, ANSI_BOLD ANSI_BLUE "\n[INFO] Processing finished.\n" ANSI_RESET);
    }
    free(buf);
    return FALSE;
}

/* Log start of processing for a file or stdin */
void audit_start(f_state *s, f_info *i) {
    if (!get_mode(s, mode_quiet)) {
        fprintf(stderr, ANSI_BOLD ANSI_BLUE "[INFO] Processing: %s\n" ANSI_RESET,
                i->file_name);
    }
    audit_msg(s, FOREMOST_DIVIDER);
    audit_msg(s, "File: %s", i->file_name);
    audit_msg(s, "Start: %s", current_time());
}

/* Log finish time of processing */
void audit_finish(f_state *s, f_info *i) {
    audit_msg(s, "Finish: %s", current_time());
}

/* Open input file, determine size, run processing, then clean up */
int process_file(f_state *s) {
    f_info *i = malloc(sizeof(f_info));
    char temp[PATH_MAX];

    if (!realpath(s->input_file, temp)) {
        print_error(s, s->input_file, strerror(errno));
        return TRUE;
    }
    i->file_name = strdup(s->input_file);
    i->is_stdin   = FALSE;
    audit_start(s, i);

#if defined(__LINUX)
#ifdef DEBUG
    printf("Using 64 bit fopen\n");
#endif
    i->handle = fopen64(i->file_name, "rb");
#elif defined(__WIN32)
    i->handle = fopen(i->file_name, "rb");
#else
    i->handle = fopen(i->file_name, "rb");
#endif

    if (!i->handle) {
        print_error(s, s->input_file, strerror(errno));
        audit_msg(s, "Error: %s", strerror(errno));
        return TRUE;
    }

    i->total_bytes = find_file_size(i->handle);
    search_stream(s, i);
    audit_finish(s, i);
    fclose(i->handle);
    free(i);
    return FALSE;
}
