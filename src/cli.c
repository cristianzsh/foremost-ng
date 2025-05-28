/* FOREMOST-NG
 *
 * Originally developed as FOREMOST by Jesse Kornblum, Kris Kendall, & Nick Mikus
 * Modified and extended by Cristian Souza
 */

#include "main.h"

// Displays a fatal error message, logs it if audit is enabled, and exits the program.
void fatal_error(f_state *s, char *msg) {
    fprintf(stderr, "%s: %s%s", __progname, msg, NEWLINE);

    if (get_audit_file_open(s)) {
        audit_msg(s, msg);
        close_audit_file(s);
    }

    exit(EXIT_FAILURE);
}

// Prints an error message unless the quiet mode is active.
void print_error(f_state *s, char *fn, char *msg) {
    if (!get_mode(s, mode_quiet)) {
        fprintf(stderr, "%s: %s: %s%s", __progname, fn, msg, NEWLINE);
    }
}

// Prints a formatted message followed by a newline.
void print_message(f_state *s, char *format, va_list argp) {
    vfprintf(stdout, format, argp);
    fprintf(stdout, "%s", NEWLINE);
}
