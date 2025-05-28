/* FOREMOST-NG
 *
 * Originally developed as FOREMOST by Jesse Kornblum, Kris Kendall, & Nick Mikus
 * Modified and extended by Cristian Souza
 */

#include "main.h"
#include <stdlib.h>
#include <string.h>
#include "ansi_colors.h"
#include <unistd.h>
#include <stdio.h>
#include <dirent.h>

#ifdef _WIN32
#include <windows.h>
char *__progname = NULL;
#endif

// Global state variables
struct DIRECTORY *dirlist = NULL;
struct DIRECTORY *dl = NULL;
char wildcard = 0;
s_spec search_spec[50];
int signal_caught = 0;

#ifdef _WIN32
/**
 * Enables ANSI escape sequence processing in Windows console.
 */
void enable_virtual_terminal_processing(void) {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD dwMode = 0;
    if (hOut != INVALID_HANDLE_VALUE && GetConsoleMode(hOut, &dwMode)) {
        dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
        SetConsoleMode(hOut, dwMode);
    }
}
#endif

/**
 * Extracts the basename from a file path (cross-platform).
 */
char *my_basename(char *path) {
    if (!path || !*path) {
        return (char *)"";
    }
    char *base = strrchr(path, '/');

#ifdef _WIN32
    char *alt = strrchr(path, '\\');
    if (alt && (!base || alt > base)) {
        base = alt;
    }
#endif

    return base ? base + 1 : path;
}

/**
 * Signal handler to track interrupt signals like SIGINT.
 */
void catch_alarm(int signum) {
    signal_caught = signum;
    signal(signum, catch_alarm);
}

/**
 * Registers signal handlers for graceful termination.
 */
void register_signal_handler(void) {
    signal_caught = 0;
    if (signal(SIGINT, catch_alarm) == SIG_IGN) {
        signal(SIGINT, SIG_IGN);
    }

    if (signal(SIGTERM, catch_alarm) == SIG_IGN) {
        signal(SIGTERM, SIG_IGN);
    }
}

/**
 * Displays a short help message.
 */
void try_msg(void) {
    fprintf(stderr, "Try `%s -h` for more information.%s", __progname, NEWLINE);
}

/**
 * Prints usage/help instructions to stderr.
 */
void usage(void) {
    fprintf(stderr, ANSI_BOLD ANSI_CYAN "%s version %s by %s.%s" ANSI_RESET,
            __progname, VERSION, AUTHOR, NEWLINE);
    fprintf(stderr, ANSI_YELLOW
            "%s %s [-v|-V|-h|-T|-Q|-q|-a|-w|-d|-x] [-t <type>] [-s <blocks>] [-k <size>]\n"
            "\t[-b <size>] [-c <file>] [-o <dir>] [-i <file>] <input files...>%s%s" ANSI_RESET,
            CMD_PROMPT, __progname, NEWLINE, NEWLINE);
    fprintf(stderr, ANSI_GREEN "Options:\n" ANSI_RESET);
    fprintf(stderr, "  " ANSI_CYAN "-V" ANSI_RESET "  Display copyright info and exit.\n");
    fprintf(stderr, "  " ANSI_CYAN "-t" ANSI_RESET "  Specify file type (e.g., jpeg,pdf).\n");
    fprintf(stderr, "  " ANSI_CYAN "-d" ANSI_RESET "  Enable indirect block detection.\n");
    fprintf(stderr, "  " ANSI_CYAN "-i" ANSI_RESET "  Specify a single input file.\n");
    fprintf(stderr, "  " ANSI_CYAN "-a" ANSI_RESET "  Write all headers, skip error detection.\n");
    fprintf(stderr, "  " ANSI_CYAN "-w" ANSI_RESET "  Only write audit file.\n");
    fprintf(stderr, "  " ANSI_CYAN "-o" ANSI_RESET "  Set output directory (default: %s).\n", DEFAULT_OUTPUT_DIRECTORY);
    fprintf(stderr, "  " ANSI_CYAN "-c" ANSI_RESET "  Set config file (default: %s).\n", DEFAULT_CONFIG_FILE);
    fprintf(stderr, "  " ANSI_CYAN "-q" ANSI_RESET "  Enable quick mode (512-byte steps).\n");
    fprintf(stderr, "  " ANSI_CYAN "-Q" ANSI_RESET "  Enable quiet mode.\n");
    fprintf(stderr, "  " ANSI_CYAN "-x" ANSI_RESET "  Enable VirusTotal scan (needs API key).\n");
    fprintf(stderr, "  " ANSI_CYAN "-v" ANSI_RESET "  Enable verbose mode.\n");
}

/**
 * Parses command-line arguments and updates the state accordingly.
 */
void process_command_line(int argc, char **argv, f_state *s) {
    int i;
    char *ptr1, *ptr2;

    while ((i = getopt(argc, argv, "o:b:c:t:s:i:k:hqmQTadvVwx")) != -1) {
        switch (i) {
            case 'v': set_mode(s, mode_verbose); break;
            case 'd': set_mode(s, mode_ind_blk); break;
            case 'w': set_mode(s, mode_write_audit); break;
            case 'a': set_mode(s, mode_write_all); break;
            case 'b': set_block(s, atoi(optarg)); break;
            case 'o': set_output_directory(s, optarg); break;
            case 'q': set_mode(s, mode_quick); break;
            case 'Q': set_mode(s, mode_quiet); break;
            case 'x': set_mode(s, mode_virustotal); break;
            case 'c': set_config_file(s, optarg); break;
            case 'm': set_mode(s, mode_multi_file); break;
            case 'k': set_chunk(s, atoi(optarg)); break;
            case 's': set_skip(s, atoi(optarg)); break;
            case 'i': set_input_file(s, optarg); break;
            case 'T': s->time_stamp = TRUE; break;
            case 't':
                // Parse multiple file types separated by commas
                ptr1 = ptr2 = optarg;
                while (1) {
                    if (!*ptr2) {
                        if (!set_search_def(s, ptr1, 0)) {
                            usage();
                            exit(EXIT_SUCCESS);
                        }
                        break;
                    }
                    if (*ptr2 == ',') {
                        *ptr2 = '\0';

                        if (!set_search_def(s, ptr1, 0)) {
                            usage();
                            exit(EXIT_SUCCESS);
                        }

                        *ptr2++ = ',';
                        ptr1 = ptr2;
                    } else {
                        ptr2++;
                    }
                }
                break;
            case 'h': usage(); exit(EXIT_SUCCESS);
            case 'V':
                printf("%s%s", VERSION, NEWLINE);
                printf("%s", COPYRIGHT);
                exit(EXIT_SUCCESS);
            default: try_msg(); exit(EXIT_FAILURE);
        }
    }

#ifdef __DEBUG
    dump_state(s);
#endif
}

/**
 * Checks if a file exists and is not a directory.
 */
static int is_valid_input(const char *path) {
    FILE *file = fopen(path, "rb");
    DIR *dir = opendir(path);
    int valid = (file != NULL && dir == NULL);

    if (file) {
        fclose(file);
    }

    if (dir) {
        closedir(dir);
    }

    return valid;
}

/**
 * Entry point for foremost-ng. Orchestrates the full recovery pipeline.
 */
int main(int argc, char **argv) {
    f_state *s = malloc(sizeof(f_state));
    int input_files = 0;
    int i;

#ifdef _WIN32
    enable_virtual_terminal_processing();
#endif

#ifndef __GLIBC__
    __progname = my_basename(argv[0]);
#endif

    if (argc < 2) {
        usage();
        return EXIT_SUCCESS;
    }

    if (initialize_state(s, argc, argv)) {
        fatal_error(s, "Unable to initialize state");
    }

    register_signal_handler();
    process_command_line(argc, argv, s);

    if (load_config_file(s)) {
        fatal_error(s, "Unable to load the config file");
    }

    if (s->num_builtin == 0) {
        set_search_def(s, "all", 0);
    }

    // First pass: count valid input files (non-option arguments start at optind)
    for (i = optind; i < argc; i++) {
        if (is_valid_input(argv[i])) {
            input_files++;
        } else {
            fprintf(stderr, ANSI_RED "[!] File not found or is a directory: %s\n" ANSI_RESET, argv[i]);
        }
    }

    if (input_files == 0) {
        fprintf(stderr, ANSI_RED "[!] No valid input files to process.\n" ANSI_RESET);
        free_state(s);
        free(s);
        return EXIT_FAILURE;
    }

    if (create_output_directory(s)) {
        fatal_error(s, "Unable to open output directory");
    }

    if (!get_mode(s, mode_write_audit)) {
        create_sub_dirs(s);
    }

    if (open_audit_file(s)) {
        fatal_error(s, "Can't open audit file");
    }

    if (input_files > 1) {
        set_mode(s, mode_multi_file);
    }

    // Second pass: process each valid input file
    for (i = optind; i < argc; i++) {
        if (is_valid_input(argv[i])) {
            set_input_file(s, argv[i]);
            process_file(s);
        }
    }

    print_stats(s);
    cleanup_output(s);

    if (close_audit_file(s)) {
        print_error(s, AUDIT_FILE_NAME, "Error closing audit file");
    }

    free_state(s);
    free(s);
    return EXIT_SUCCESS;
}
