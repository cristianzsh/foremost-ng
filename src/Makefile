RAW_CC = gcc
RAW_FLAGS = -Wall -O2
LINK_OPT =
VERSION = 1.5.7

# Set default output file name
NAME = foremost-ng
GOAL = $(NAME)

# Try to determine the host system
SYS := $(shell uname -s | tr -d "[0-9]" | tr -d "-" | tr "[A-Z]" "[a-z]")

# Use Clang on OpenBSD and FreeBSD
ifeq ($(filter $(SYS),openbsd freebsd),$(SYS))
RAW_CC = clang
endif

# Where we get installed
BIN = /usr/local/bin
MAN = /usr/share/man/man8
CONF = /usr/local/etc

# Correctly quote VERSION string
RAW_FLAGS += -DVERSION="\"$(VERSION)\""

# Setup for compiling and cross-compiling for Windows
CR_CC = x86_64-w64-mingw32-gcc
CR_FLAGS = -Wall -O2 -DVERSION="\"$(VERSION)\"" -D__WIN32 -fPIC
CR_LINK = -fPIC
CR_STRIP = x86_64-w64-mingw32-strip
CR_GOAL = $(NAME).exe
WINCC = $(RAW_CC) $(RAW_FLAGS) -D__WIN32

# Generic "how to compile C files"
CC = $(RAW_CC) $(RAW_FLAGS) -D__UNIX
.c.o:
	$(CC) -c $<

# Definitions
HEADER_FILES = main.h ole.h extract.h
SRC = main.c state.c helpers.c config.c cli.c engine.c dir.c extract.c api.c
OBJ = main.o state.o helpers.o config.o cli.o engine.o dir.o extract.o api.o
DOCS = Makefile README CHANGES $(MAN_PAGES) foremost.conf
WINDOC = README.txt CHANGES.txt
MAN_PAGES = $(NAME).8.gz

#---------------------------------------------------------------------
# BUILD TARGETS
#---------------------------------------------------------------------

all: $(SYS) goals

goals: $(GOAL)

linux: CC += -D__LINUX -DLARGEFILE64_SOURCE -D_FILE_OFFSET_BITS=64
linux: goals

darwin mac: CC += -D__MACOSX
darwin mac: goals

netbsd openbsd freebsd unix: goals

engine.o: engine.c
	$(CC) -c engine.c

# Windows / MinGW targets
win_general: LINK_OPT = $(CR_LINK)
win_general: GOAL = $(CR_GOAL)
win_general: goals
	$(STRIP) $(CR_GOAL)

cross: CC = $(CR_CC) $(CR_FLAGS)
cross: STRIP = $(CR_STRIP)
cross: win_general

windows: CC = $(WINCC)
windows: STRIP = strip
windows: win_general

cygwin_nt. cygwin: unix

#---------------------------------------------------------------------
# LINK FINAL BINARY
#---------------------------------------------------------------------

$(GOAL): $(OBJ)
	$(CC) $(OBJ) -o $(GOAL) $(LINK_OPT)

#---------------------------------------------------------------------
# INSTALLATION
#---------------------------------------------------------------------

install: goals
	install -m 755 $(GOAL) $(BIN)
	install -m 444 $(MAN_PAGES) $(MAN)
	install -m 444 foremost.conf $(CONF)

macinstall: BIN = /usr/local/bin/
macinstall: MAN = /usr/share/man/man1/
macinstall: CONF = /usr/local/etc/
macinstall: mac install

uninstall:
	rm -f -- $(BIN)/$(GOAL)
	rm -f -- $(MAN)/$(MAN_PAGES)

macuninstall: BIN = /usr/bin
macuninstall: MAN = /usr/share/man/man1
macuninstall: uninstall

#---------------------------------------------------------------------
# CLEAN
#---------------------------------------------------------------------

preflight:
	grep -n RBF *.1 *.h *.c README CHANGES

nice:
	rm -f -- *~

clean: nice
	rm -f -- *.o
	rm -f -- $(CR_GOAL) $(NAME) $(WINDOC)
	rm -f -- $(TAR_FILE).gz $(DEST_DIR).zip $(DEST_DIR).zip.gpg

#---------------------------------------------------------------------
# PACKAGE
#---------------------------------------------------------------------

EXTRA_FILES =
DEST_DIR = $(NAME)-$(VERSION)
TAR_FILE = $(DEST_DIR).tar
PKG_FILES = $(SRC) $(HEADER_FILES) $(DOCS) $(EXTRA_FILES)

package: clean
	rm -f $(TAR_FILE) $(TAR_FILE).gz
	mkdir $(DEST_DIR)
	cp $(PKG_FILES) $(DEST_DIR)
	tar cvf $(TAR_FILE) $(DEST_DIR)
	rm -rf $(DEST_DIR)
	gzip $(TAR_FILE)

win-doc:
	/usr/bin/tbl ./$(MD5GOAL).1 | /usr/bin/groff -S -Wall -mtty-char -mandoc -Tascii | /usr/bin/col > README.txt
	cp CHANGES CHANGES.txt
	flip -d $(WINDOC)

cross-pkg: clean cross win-doc
	rm -f $(DEST_DIR).zip
	zip $(DEST_DIR).zip $(CR_GOAL) $(WINDOC)
	rm -f $(WINDOC)

world: package cross-pkg
