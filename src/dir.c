/* FOREMOST-NG
 *
 * Originally developed as FOREMOST by Jesse Kornblum, Kris Kendall, & Nick Mikus
 * Modified and extended by Cristian Souza
 */

#include "main.h"
#include "ansi_colors.h"
#include "vt_query.h"
#include <inttypes.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include <dirent.h>

#ifdef _WIN32
#  include <direct.h>
#endif

// Return TRUE if directory has only “.” and “..”
int is_empty_directory(DIR *dir_stream) {
    // Read three entries: if third exists, directory is not empty
    if (readdir(dir_stream) && readdir(dir_stream) && readdir(dir_stream)) {
        return FALSE;
    }

    return TRUE;
}

// Remove any empty subdirectories under the output directory
void cleanup_output(f_state *s) {
    char path[MAX_STRING_LENGTH];
    DIR *d = opendir(get_output_directory(s));
    struct dirent *e;

    if (!d) {
        return;
    }

    while ((e = readdir(d))) {
        // Build full path for entry
        snprintf(path, sizeof(path), "%s/%s",
                 get_output_directory(s), e->d_name);
        DIR *sub = opendir(path);
        if (sub) {
            // If subdir is empty, remove it
            if (is_empty_directory(sub)) {
                rmdir(path);
            }

            closedir(sub);
        }
    }
    closedir(d);
}

// Make one directory; only error if it fails for reasons other than EEXIST
int make_new_directory(f_state *s, char *fn) {
#ifdef _WIN32
    if (_mkdir(fn) != 0) {
#else
    mode_t m = S_IRUSR|S_IWUSR|S_IXUSR|S_IRGRP|S_IWGRP|S_IXGRP|S_IROTH|S_IWOTH;
    if (mkdir(fn, m) != 0) {
#endif
        // If directory already exists, that's OK
        if (errno != EEXIST) {
            print_error(s, fn, strerror(errno));
            return TRUE;
        }
    }
    return FALSE;
}

// Replace spaces and colons in timestamp with underscores
char *clean_time_string(char *t) {
    for (size_t i = 0; t[i]; i++) {
#ifdef _WIN32
        // On Windows, only replace ':' that is not drive letter
        if (t[i] == ':' && t[i+1] != '\\') {
            t[i] = '_';
        }
#else
        if (t[i] == ' ' || t[i] == ':') {
            t[i] = '_';
        }
#endif
    }
    return t;
}

// Ensure output directory exists and is empty, or create it
int create_output_directory(f_state *s) {
    DIR *d;
    char tmp[MAX_STRING_LENGTH] = {0};

    if (s->time_stamp) {
        // Append timestamp to directory name
        snprintf(tmp, sizeof(tmp), "%s_%s",
                 get_output_directory(s), get_start_time(s));
        clean_time_string(tmp);
        set_output_directory(s, tmp);
    }

#ifdef DEBUG
    printf("Checking output dir %s\n", get_output_directory(s));
#endif

    d = opendir(get_output_directory(s));
    if (d) {
        // Directory exists: must be empty
        if (!is_empty_directory(d)) {
            printf(ANSI_BOLD ANSI_RED "[ERROR] " ANSI_RESET
                   "%s not empty\n", get_output_directory(s));
            exit(EXIT_FAILURE);
        }
        closedir(d);
        return FALSE;
    }

    // If error is something other than "does not exist", report it
    if (errno != ENOENT) {
        print_error(s, get_output_directory(s), strerror(errno));
        return TRUE;
    }

    // Reject empty output directory name
    if (get_output_directory(s)[0] == '\0') {
        print_error(s, "(output_directory)", "Name unknown");
        return TRUE;
    }

    // Create the directory
    return make_new_directory(s, get_output_directory(s));
}

// Create subdirectories for each file type (and related types)
int create_sub_dirs(f_state *s) {
    char path[MAX_STRING_LENGTH];
    const char ole[7][4]  = { "ppt","doc","xls","sdw","mbd","vis","ole" };
    const char riff[2][4] = { "avi","wav" };
    const char zip[8][5]  = { "sxc","sxw","sxi","sx","jar","docx","pptx","xlsx" };

    for (int i = 0; i < s->num_builtin; i++) {
        // Base suffix dir
        snprintf(path, sizeof(path), "%s/%s",
                 get_output_directory(s), search_spec[i].suffix);
        make_new_directory(s, path);

        // OLE group handling
        if (search_spec[i].type == OLE || get_mode(s, mode_write_all)) {
            for (int j = 0; j < 7; j++) {
                // Skip own suffix
                if (!strstr(path, ole[j])) {
                    snprintf(path, sizeof(path), "%s/%s",
                             get_output_directory(s), ole[j]);
                    make_new_directory(s, path);
                }
            }
        }

        // EXE group => add dll dir
        if (search_spec[i].type == EXE) {
            snprintf(path, sizeof(path), "%s/dll",
                     get_output_directory(s));
            make_new_directory(s, path);
        }

        // RIFF group handling
        if (search_spec[i].type == RIFF || get_mode(s, mode_write_all)) {
            for (int j = 0; j < 2; j++) {
                if (!strstr(path, riff[j])) {
                    snprintf(path, sizeof(path), "%s/%s",
                             get_output_directory(s), riff[j]);
                    make_new_directory(s, path);
                }
            }
        }

        // ZIP group handling
        if (search_spec[i].type == ZIP || get_mode(s, mode_write_all)) {
            for (int j = 0; j < 8; j++) {
                if (!strstr(path, zip[j])) {
                    snprintf(path, sizeof(path), "%s/%s",
                             get_output_directory(s), zip[j]);
                    make_new_directory(s, path);
                }
            }
        }
    }
    return TRUE;
}

// Write recovered data to disk, handle naming and optional VT lookup
int write_to_disk(f_state *s, s_spec *nd,
                  uint64_t len, unsigned char *buf,
                  uint64_t t_off) {
    char fn[MAX_STRING_LENGTH], col[32] = {0}, tmp[32];
    char dir_only[MAX_STRING_LENGTH];
    uint64_t blk = t_off / s->block_size;
    int idx = 1;
    FILE *f, *tst;
    long w;

    nd->written = TRUE;
    snprintf(nd->vt_label, sizeof(nd->vt_label), "N/A");

    if (get_mode(s, mode_write_audit)) {
        if (!nd->comment[0]) strcpy(nd->comment, " ");
        snprintf(col, sizeof(col), "%08" PRIuMAX ".%s", (uintmax_t) blk, nd->suffix);
        audit_msg(s, "%2d: %-20s %10s %12llu  %-24s  %-15s",
                  s->fileswritten, col,
                  human_readable(len, tmp),
                  t_off, nd->comment, nd->vt_label);
        s->fileswritten++; nd->found++;
        return TRUE;
    }

    // Ensure subdir exists
    snprintf(dir_only, sizeof(dir_only), "%s/%s",
             s->output_directory, nd->suffix);
    make_new_directory(s, dir_only);

    // Build initial filename
    snprintf(fn, sizeof(fn), "%s/%s/%0*" PRIuMAX ".%s",
             s->output_directory, nd->suffix,
             8, (uintmax_t) blk, nd->suffix);

    tst = fopen(fn, "rb");
    while (tst) {
        fclose(tst);
        idx++;
        snprintf(fn, sizeof(fn),
                 "%s/%s/%0*" PRIuMAX "_%d.%s",
                 s->output_directory, nd->suffix,
                 8, (uintmax_t) blk, idx, nd->suffix);
        tst = fopen(fn, "rb");
    }

    // Try to open for writing; on failure, show path then abort
    if (!(f = fopen(fn, "wb"))) {
        printf("fn = %s  failed\n", fn);
        fatal_error(s, "Can't open file for writing \n");
    }

    // Write and close
    w = fwrite(buf, 1, len, f);
    if (w != (long)len) {
        fatal_error(s, "Write error\n");
    }

    if (fclose(f)) {
        fatal_error(s, "Close error\n");
    }

    if (!nd->comment[0]) {
        strcpy(nd->comment, " ");
    }

    // VirusTotal check
    if (get_mode(s, mode_virustotal)) {
        char sha256[65];
        VTResult vt = {0};
        sha_checksum(fn, "sha256", sha256);
        vt = vt_check_hash(sha256);
        snprintf(nd->vt_label, sizeof(nd->vt_label),
                 vt.is_malicious ? "Malicious (%d)" : "Clean (%d)",
                 vt.is_malicious ? vt.malicious_count : vt.undetected_count);
    }

    // Final audit log
    if (idx == 1) {
        snprintf(col, sizeof(col), "%08" PRIuMAX ".%s", (uintmax_t) blk, nd->suffix);
    } else {
        snprintf(col, sizeof(col), "%08" PRIuMAX "_%d.%s", (uintmax_t) blk, idx-1, nd->suffix);
    }

    audit_msg(s, "%4d: %-20s %10s %12llu  %-24s  %-15s",
              s->fileswritten, col,
              human_readable(len, tmp),
              t_off, nd->comment, nd->vt_label);

    s->fileswritten++;
    nd->found++;
    return TRUE;
}
