/* FOREMOST-NG
 *
 * Originally developed as FOREMOST by Jesse Kornblum, Kris Kendall, & Nick Mikus
 * Modified and extended by Cristian Souza
 */

#include "main.h"

/**
 * Translates escape sequences in a string (e.g., \n, \t, \xHH) and modifies it in place.
 * Returns the length of the translated string.
 */
int translate(char *str) {
    char next;
    char *rd = str, *wr = str, *bad;
    char temp[1 + 3 + 1]; // "0" + 3 chars + null terminator
    char ch;

    if (!*rd) {
        return 0;
    }

    while (*rd) {
        if (*rd == '\\') {
            rd++;
            switch (*rd) {
                case '\\': ++(*rd); *wr++ = '\\'; break;
                case 'a':  ++(*rd); *wr++ = '\a'; break;
                case 's':  ++(*rd); *wr++ = ' ';  break;
                case 'n':  ++(*rd); *wr++ = '\n'; break;
                case 'r':  ++(*rd); *wr++ = '\r'; break;
                case 't':  ++(*rd); *wr++ = '\t'; break;
                case 'v':  ++(*rd); *wr++ = '\v'; break;

                // Hex or octal handling (3-character escape like \xAF)
                case 'x': case '0': case '1': case '2': case '3':
                    next = *(rd + 1);
                    if (next < 48 || (57 < next && next < 65) ||
                        (70 < next && next < 97) || next > 102)
                        break;

                    next = *(rd + 2);
                    if (next < 48 || (57 < next && next < 65) ||
                        (70 < next && next < 97) || next > 102)
                        break;

                    temp[0] = '0';
                    bad = temp;
                    strncpy(temp + 1, rd, 3);
                    temp[4] = '\0';
                    ch = strtoul(temp, &bad, 0);
                    if (*bad == '\0') {
                        *wr++ = ch;
                        rd += 3;
                    }
                    break;

                default:
                    *wr++ = '\\';
                    break;
            }
        } else {
            *wr++ = *rd++;
        }
    }

    *wr = '\0';
    return wr - str;
}

/**
 * Skips whitespace characters at the beginning of a string.
 */
char *skipWhiteSpace(char *str) {
    while (isspace(str[0])) str++;
    return str;
}

/**
 * Extracts and processes a config line split into tokens.
 */
int extractSearchSpecData(f_state *state, char **tokenarray) {
    s_spec *s = &search_spec[state->num_builtin];

    s->suffix = malloc(MAX_SUFFIX_LENGTH * sizeof(char));
    s->header = malloc(MAX_STRING_LENGTH * sizeof(char));
    s->footer = malloc(MAX_STRING_LENGTH * sizeof(char));
    s->type = CONF;

    if (!strncasecmp(tokenarray[0], FOREMOST_NOEXTENSION_SUFFIX, strlen(FOREMOST_NOEXTENSION_SUFFIX))) {
        s->suffix[0] = ' ';
        s->suffix[1] = 0;
    } else {
        memcpy(s->suffix, tokenarray[0], MAX_SUFFIX_LENGTH);
    }

    s->case_sen = (!strncasecmp(tokenarray[1], "y", 1) || !strncasecmp(tokenarray[1], "yes", 3));
    s->max_len = atoi(tokenarray[2]);

    s->searchtype = SEARCHTYPE_FORWARD;
    if (!strncasecmp(tokenarray[5], "REVERSE", strlen("REVERSE"))) {
        s->searchtype = SEARCHTYPE_REVERSE;
    } else if (!strncasecmp(tokenarray[5], "NEXT", strlen("NEXT"))) {
        s->searchtype = SEARCHTYPE_FORWARD_NEXT;
    } else if (!strncasecmp(tokenarray[5], "FORWARD", strlen("FORWARD"))) {
        s->searchtype = SEARCHTYPE_FORWARD;
    } else if (!strncasecmp(tokenarray[5], "ASCII", strlen("ASCII"))) {
        s->searchtype = SEARCHTYPE_ASCII;
    }

    s->header_len = translate(tokenarray[3]);
    memcpy(s->header, tokenarray[3], s->header_len);
    s->footer_len = translate(tokenarray[4]);
    memcpy(s->footer, tokenarray[4], s->footer_len);

    init_bm_table(s->header, s->header_bm_table, s->header_len, s->case_sen, s->searchtype);
    init_bm_table(s->footer, s->footer_bm_table, s->footer_len, s->case_sen, s->searchtype);

    return TRUE;
}

/**
 * Processes a single line from the config file.
 */
int process_line(f_state *s, char *buffer, int line_number) {
    char *buf = buffer;
    char *token;
    char **tokenarray = (char **)malloc(6 * sizeof(char[MAX_STRING_LENGTH]));
    int i = 0, len = strlen(buffer);

    if (len == MAX_STRING_LENGTH - 1) {
        if (!(buffer[len - 1] == '\n') || !(buffer[len - 2] == 0x0d && buffer[len - 1] == 0x0a)) {
            fprintf(stderr, "\nERROR: Foremost does not support lines longer than %d. Check line %d.\n", MAX_STRING_LENGTH, line_number);
            return FALSE;
        }
    }

    // Strip CRLF from Windows-style lines
    if (buffer[len - 2] == 0x0d && buffer[len - 1] == 0x0a) {
        buffer[len - 2] = buffer[len - 1];
        buffer[len - 1] = buffer[len];
    }

    buf = skipWhiteSpace(buf);
    token = strtok(buf, " \t\n");

    // Ignore comments and blank lines
    if (token == NULL || token[0] == '#') {
        return TRUE;
    }

    // Handle wildcard directive
    if (!strncasecmp(token, "wildcard", 9)) {
        if ((token = strtok(NULL, " \t\n")) != NULL) {
            translate(token);
        } else {
            return TRUE;
        }

        if (strlen(token) > 1) {
            fprintf(stderr,
                "Warning: Wildcard can only be one character, but you specified %zu characters.\n"
                "         Using the first character, \"%c\", as the wildcard.\n",
                strlen(token), token[0]);
        }

        wildcard = token[0];
        return TRUE;
    }

    // Tokenize line into parts
    while (token && (i < NUM_SEARCH_SPEC_ELEMENTS)) {
        tokenarray[i++] = token;
        token = strtok(NULL, " \t\n");
    }

    // Pad missing tokens with empty strings
    switch (NUM_SEARCH_SPEC_ELEMENTS - i) {
        case 2:
            tokenarray[NUM_SEARCH_SPEC_ELEMENTS - 2] = "";
            tokenarray[NUM_SEARCH_SPEC_ELEMENTS - 1] = "";
            break;
        case 1:
            tokenarray[NUM_SEARCH_SPEC_ELEMENTS - 1] = "";
            break;
        case 0:
            break;
        default:
            fprintf(stderr, "\nERROR: In line %d of the configuration file.\n", line_number);
            return FALSE;
    }

    if (s->num_builtin >= MAX_BUILTIN) {
        fprintf(stderr, "\nERROR: Reached maximum amount of entries. Line: %d. Maximum: %d\n", line_number, MAX_BUILTIN);
        return FALSE;
    }

    if (!extractSearchSpecData(s, tokenarray)) {
        fprintf(stderr, "\nERROR: Unknown error on line %d of the configuration file.\n", line_number);
    }

    s->num_builtin++;
    return TRUE;
}

/**
 * Loads the configuration file and processes each line.
 */
int load_config_file(f_state *s) {
    FILE *f;
    char *buffer = (char *)malloc(MAX_STRING_LENGTH * sizeof(char));
    off_t line_number = 0;

#ifdef __DEBUG
    printf("About to open config file %s%s", get_config_file(s), NEWLINE);
#endif

    if ((f = fopen(get_config_file(s), "r")) == NULL) {
        // Try fallback location
#ifdef __WIN32
        set_config_file(s, "/Program Files/foremost/foremost.conf");
#else
        set_config_file(s, "/usr/local/etc/foremost.conf");
#endif
        if ((f = fopen(get_config_file(s), "r")) == NULL) {
            print_error(s, get_config_file(s), strerror(errno));
            free(buffer);
            return TRUE;
        }
    }

    while (fgets(buffer, MAX_STRING_LENGTH, f)) {
        ++line_number;
        if (!process_line(s, buffer, line_number)) {
            free(buffer);
            fclose(f);
            return TRUE;
        }
    }

    fclose(f);
    free(buffer);
    return FALSE;
}
