/* FOREMOST-NG
 *
 * Originally developed as FOREMOST by Jesse Kornblum, Kris Kendall, & Nick Mikus
 *
 * This is a work of the US Government. In accordance with 17 USC 105,
 * copyright protection is not available for any work of the US Government.
 *
 * This version, named "foremost-ng", has been modified and extended by Cristian Souza
 * to modernize the codebase and introduce new features.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#include "main.h"
#include <stdlib.h>
#include "ansi_colors.h"

struct DIRECTORY *dirlist = NULL;
struct DIRECTORY *dl = NULL;
char wildcard = 0;
s_spec search_spec[50];
int signal_caught = 0;
#ifdef _WIN32
char *__progname = NULL;
#endif

#ifdef _WIN32
#include <windows.h>
void enable_virtual_terminal_processing() {
	HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	DWORD dwMode = 0;
	if (hOut != INVALID_HANDLE_VALUE &&
		GetConsoleMode(hOut, &dwMode)) {
		dwMode |= ENABLE_VIRTUAL_TERMINAL_PROCESSING;
	SetConsoleMode(hOut, dwMode);
		}
}
#endif

char *my_basename(char *path) {
	if (!path || !*path) return (char *)"";

	char *base = strrchr(path, '/');
	#ifdef _WIN32
	char *alt = strrchr(path, '\\');
	if (alt && (!base || alt > base)) base = alt;
	#endif
	return base ? base + 1 : path;
}

void catch_alarm(int signum)
{
	signal_caught = signum;
	signal(signum, catch_alarm);
}

void register_signal_handler(void)
{
	signal_caught = 0;

	if (signal(SIGINT, catch_alarm) == SIG_IGN)
		signal(SIGINT, SIG_IGN);
	if (signal(SIGTERM, catch_alarm) == SIG_IGN)
		signal(SIGTERM, SIG_IGN);

#ifndef __WIN32

	/* Note: I haven't found a way to get notified of
     console resize events in Win32.  Right now the statusbar
     will be too long or too short if the user decides to resize
     their console window while foremost runs.. */

	/* RBF - Handle TTY events  */

	// The function setttywidth is in the old helpers.c
	// signal(SIGWINCH, setttywidth);
#endif
}

void try_msg(void)
{
	fprintf(stderr, "Try `%s -h` for more information.%s", __progname, NEWLINE);
}

/* The usage function should, at most, display 22 lines of text to fit
   on a single screen */
void usage(void)
{
	fprintf(stderr, ANSI_BOLD ANSI_CYAN "%s version %s by %s.%s" ANSI_RESET, __progname, VERSION, AUTHOR, NEWLINE);
	fprintf(stderr, ANSI_YELLOW
			"%s %s [-v|-V|-h|-T|-Q|-q|-a|-w-d] [-t <type>] [-s <blocks>] [-k <size>] \n\t[-b <size>] [-c <file>] [-o <dir>] [-i <file] %s%s" ANSI_RESET,
		CMD_PROMPT,
			__progname,
			NEWLINE,
			NEWLINE);

	fprintf(stderr, ANSI_GREEN "Options:\n" ANSI_RESET);
	fprintf(stderr, "  " ANSI_CYAN "-V" ANSI_RESET "  Display copyright information and exit.\n");
	fprintf(stderr, "  " ANSI_CYAN "-t" ANSI_RESET "  Specify file type (e.g., jpeg,pdf).\n");
	fprintf(stderr, "  " ANSI_CYAN "-d" ANSI_RESET "  Turn on indirect block detection (for UNIX file-systems).\n");
	fprintf(stderr, "  " ANSI_CYAN "-i" ANSI_RESET "  Specify input file (default is stdin).\n");
	fprintf(stderr, "  " ANSI_CYAN "-a" ANSI_RESET "  Write all headers, perform no error detection (corrupted files).\n");
	fprintf(stderr, "  " ANSI_CYAN "-w" ANSI_RESET "  Only write the audit file, do not write any detected files to the disk.\n");
	fprintf(stderr, "  " ANSI_CYAN "-o" ANSI_RESET "  Set output directory (defaults to %s).\n", DEFAULT_OUTPUT_DIRECTORY);
	fprintf(stderr, "  " ANSI_CYAN "-c" ANSI_RESET "  Set configuration file to use (defaults to %s).\n", DEFAULT_CONFIG_FILE);
	fprintf(stderr, "  " ANSI_CYAN "-q" ANSI_RESET "  Enables quick mode. Search are performed on 512 byte boundaries.\n");
	fprintf(stderr, "  " ANSI_CYAN "-Q" ANSI_RESET "  Enables quiet mode. Suppress output messages.\n");
	fprintf(stderr, "  " ANSI_CYAN "-x" ANSI_RESET "  Scan each recovered file using VirusTotal API (requires VT_API_KEY).\n");
	fprintf(stderr, "  " ANSI_CYAN "-v" ANSI_RESET "  Verbose mode. Logs all messages to screen.\n");
}

void process_command_line(int argc, char **argv, f_state *s)
{

	int		i;
	char	*ptr1, *ptr2;

	while ((i = getopt(argc, argv, "o:b:c:t:s:i:k:hqmQTadvVwx")) != -1)
		{
		switch (i)
			{

			case 'v':
				set_mode(s, mode_verbose);
				break;

			case 'd':
				set_mode(s, mode_ind_blk);
				break;

			case 'w':
				set_mode(s, mode_write_audit);	/*Only write audit*/
				break;

			case 'a':
				set_mode(s, mode_write_all);	/*Write all headers*/
				break;

			case 'b':
				set_block(s, atoi(optarg));
				break;

			case 'o':
				set_output_directory(s, optarg);
				break;

			case 'q':
				set_mode(s, mode_quick);
				break;

			case 'Q':
				set_mode(s, mode_quiet);
				break;

			case 'x':
				set_mode(s, mode_virustotal);
				break;

			case 'c':
				set_config_file(s, optarg);
				break;

			case 'm':
				set_mode(s, mode_multi_file);

			case 'k':
				set_chunk(s, atoi(optarg));
				break;

			case 's':
				set_skip(s, atoi(optarg));
				break;

			case 'i':
				set_input_file(s, optarg);
				break;

			case 'T':
				s->time_stamp = TRUE;
				break;

			case 't':

				/*See if we have multiple file types to define*/
				ptr1 = ptr2 = optarg;
				while (1)
					{
					if (!*ptr2)
						{
						if (!set_search_def(s, ptr1, 0))
							{
							usage();
							exit(EXIT_SUCCESS);
							}
						break;
						}

					if (*ptr2 == ',')
						{
						*ptr2 = '\0';
						if (!set_search_def(s, ptr1, 0))
							{
							usage();
							exit(EXIT_SUCCESS);
							}

						*ptr2++ = ',';
						ptr1 = ptr2;
						}
					else
						{
						ptr2++;
						}
					}
				break;

			case 'h':
				usage();
				exit(EXIT_SUCCESS);

			case 'V':
				printf("%s%s", VERSION, NEWLINE);

				/* We could just say printf(COPYRIGHT), but that's a good way
	 to introduce a format string vulnerability. Better to always
	 use good programming practice... */
				printf("%s", COPYRIGHT);
				exit(EXIT_SUCCESS);

			default:
				try_msg();
				exit(EXIT_FAILURE);

			}

		}

#ifdef __DEBUG
	dump_state(s);
#endif

}

int main(int argc, char **argv)
{
	FILE	*testFile = NULL;
	f_state *s = (f_state *)malloc(sizeof(f_state));
	int		input_files = 0;
	char	**temp = argv;
	DIR* 	dir;
#ifdef _WIN32
	enable_virtual_terminal_processing();
#endif

#ifndef __GLIBC__
	__progname = my_basename(argv[0]);
#endif

	/* if no arguments given, show usage */
	if (argc < 2)
	{
		usage();
		return EXIT_SUCCESS;
	}

	/*Initialize the global state struct*/
	if (initialize_state(s, argc, argv))
		fatal_error(s, "Unable to initialize state");

	register_signal_handler();
	process_command_line(argc, argv, s);

	if (load_config_file(s))
	{
		fatal_error(s, "Unable to load the config file");
	}

	if (s->num_builtin == 0)
		{

		/*Nothing specified via the command line or the conf
	file so default to all builtin search types*/
		set_search_def(s, "all", 0);
		}
	
	if (create_output_directory(s))
		fatal_error(s, "Unable to open output directory");	

	if (!get_mode(s, mode_write_audit))
		{
		create_sub_dirs(s);
		}

	if (open_audit_file(s))
		fatal_error(s, "Can't open audit file");

	/* Scan for valid files to open */
	while (*argv != NULL)
	{
		if(strcmp(*argv,"-c")==0)
		{
			/*jump past the conf file so we don't process it.*/
			argv+=2;
		}
		testFile = fopen(*argv, "rb");
		if (testFile)
		{
			fclose(testFile);
			dir = opendir(*argv);
			
			if (strstr(s->config_file, *argv) == NULL && !dir)
			{
				input_files++;
			}
			
			if(dir) closedir(dir);		
		}

		++argv;
	}

	argv = temp;
	if (input_files > 1)
		{
		set_mode(s, mode_multi_file);
		}

	++argv;
	while (*argv != NULL)
		{
		testFile = fopen(*argv, "rb");

		if (testFile)
			{
				fclose(testFile);
				dir = opendir(*argv);
				if (strstr(s->config_file, *argv) == NULL && !dir)
				{
					set_input_file(s, *argv);
					process_file(s);
				}
				if(dir) closedir(dir);
			}

		++argv;
		}

	if (input_files == 0)
		{

		//printf("using stdin\n");
		process_stdin(s);
		}

	print_stats(s);

	/*Lets try to clean up some of the extra sub_dirs*/
	cleanup_output(s);

	if (close_audit_file(s))
		{

		/* Hells bells. This is bad, but really, what can we do about it? 
       Let's just report the error and try to get out of here! */
		print_error(s, AUDIT_FILE_NAME, "Error closing audit file");
		}

	free_state(s);
	free(s);
	return EXIT_SUCCESS;
}
