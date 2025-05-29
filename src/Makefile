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

# Installation paths
BIN = /usr/local/bin
MAN = /usr/share/man/man8
CONF = /usr/local/etc

# Correctly quote VERSION string
RAW_FLAGS += -DVERSION="\"$(VERSION)\""

# Setup for compiling and cross-compiling for Windows
CR_CC = x86_64-w64-mingw32-gcc
CR_FLAGS = -Wall -O2 -DVERSION="\"$(VERSION)\"" -D__WIN32 -fPIC
CR_LINK = -fPIC -lssl -lcrypto -lcurl -lws2_32 -lcrypt32
CR_STRIP = x86_64-w64-mingw32-strip
CR_GOAL = $(NAME).exe
WINCC = $(RAW_CC) $(RAW_FLAGS) -D__WIN32

# Include and lib paths for OpenBSD and FreeBSD
ifeq ($(filter $(SYS),openbsd freebsd),$(SYS))
RAW_FLAGS += -I/usr/local/include
LINK_OPT += -L/usr/local/lib -lcurl -lssl -lcrypto
else ifeq ($(SYS),darwin)
OPENSSL_PATH := $(shell brew --prefix openssl@3 2>/dev/null)
ifeq ($(OPENSSL_PATH),)
$(error OpenSSL not found. Install with: brew install openssl@3)
endif
RAW_FLAGS += -I$(OPENSSL_PATH)/include
LINK_OPT += -L$(OPENSSL_PATH)/lib -lssl -lcrypto -lcurl
else
LINK_OPT += -lssl -lcrypto -lcurl
endif

# Generic C compile
CC = $(RAW_CC) $(RAW_FLAGS) -D__UNIX
.c.o:
	$(CC) -c $<

# Source and object files
HEADER_FILES = main.h ole.h extract.h vt_query.h
SRC = main.c state.c helpers.c config.c cli.c engine.c dir.c extract.c api.c vt_query.c
OBJ = main.o state.o helpers.o config.o cli.o engine.o dir.o extract.o api.o vt_query.o
DOCS = Makefile $(MAN_PAGES) foremost.conf
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
	@echo "Installing binary to $(BIN)"
	install -d $(BIN)
	install -m 755 $(GOAL) $(BIN)

	@echo "Installing man page to $(MAN)"
	install -d $(MAN)
	install -m 444 $(MAN_PAGES) $(MAN)

	@echo "Installing config to $(CONF)"
	install -d $(CONF)
	install -m 444 foremost.conf $(CONF)

macinstall: BIN = /usr/local/bin
macinstall: MAN = /usr/local/share/man/man8
macinstall: CONF = /usr/local/etc
macinstall: install

uninstall:
	rm -f -- $(BIN)/$(GOAL)
	rm -f -- $(MAN)/$(MAN_PAGES)

macuninstall: BIN = /usr/local/bin
macuninstall: MAN = /usr/local/share/man/man8
macuninstall: uninstall

#---------------------------------------------------------------------
# CLEAN
#---------------------------------------------------------------------

preflight:
	grep -n RBF *.1 *.h *.c

nice:
	rm -f -- *~

clean: nice
	rm -f -- *.o
	rm -f -- $(CR_GOAL) $(NAME)
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

cross-pkg: clean cross
	rm -f $(DEST_DIR).zip
	zip $(DEST_DIR).zip $(CR_GOAL)

world: package cross-pkg

.PHONY: all clean install uninstall macinstall macuninstall package cross-pkg goals
