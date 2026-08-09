# Standalone build for the tcgcov TCG plugin.
#
# Upstream QEMU builds contrib/plugins/*.c with its own Makefile, which needs a
# configured QEMU tree. tcgcov lives outside QEMU, so this builds against just
# the plugin header and glib.
#
#   make QEMU_INCLUDE=/path/to/qemu/include            # from a QEMU checkout
#   make QEMU_PLUGIN_H=/path/to/qemu-plugin.h          # from a single header
#
# The header must match the QEMU you will load the plugin into: the plugin API
# is versioned via QEMU_PLUGIN_VERSION and QEMU refuses to load a mismatch.
#
# Output: libtcgcov.so  (pass to QEMU as -plugin ./libtcgcov.so,...)

NAME      := tcgcov
SO        := lib$(NAME).so
SRC       := $(NAME).c

# Point at a QEMU source tree's include/ directory, or at a bare header.
QEMU_INCLUDE ?=
QEMU_PLUGIN_H ?=

CFLAGS    ?= -O2 -g
CFLAGS    += -std=gnu11 -Wall -Wextra -fPIC
CFLAGS    += $(shell pkg-config --cflags glib-2.0)
LDFLAGS   += -shared
LIBS      := $(shell pkg-config --libs glib-2.0)

ifneq ($(QEMU_INCLUDE),)
# The header ships as <qemu-source>/include/qemu/qemu-plugin.h but is included
# as <qemu-plugin.h>, so both directories are needed -- QEMU's own
# contrib/plugins build does the same.
CFLAGS    += -I$(QEMU_INCLUDE) -I$(QEMU_INCLUDE)/qemu
endif
ifneq ($(QEMU_PLUGIN_H),)
CFLAGS    += -I$(dir $(QEMU_PLUGIN_H))
endif

# Feature probe: discontinuity callbacks were added part-way through plugin API
# version 5 with no version bump, so QEMU_PLUGIN_VERSION cannot distinguish a
# header that has them from one that does not. Look for the symbol itself.
PLUGIN_HEADER := $(firstword $(wildcard $(QEMU_PLUGIN_H) \
                                        $(QEMU_INCLUDE)/qemu/qemu-plugin.h \
                                        $(QEMU_INCLUDE)/qemu-plugin.h))
HAVE_DISCON := $(shell grep -qs qemu_plugin_register_vcpu_discon_cb \
                         "$(PLUGIN_HEADER)" && echo 1 || echo 0)
CFLAGS    += -DTCGCOV_HAVE_DISCON=$(HAVE_DISCON)

UNAME_S   := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
# macOS builds the plugin as a bundle and needs undefined symbols left to the
# host, since qemu_plugin_* are resolved by the QEMU binary at load time.
LDFLAGS   := -bundle -undefined dynamic_lookup
SO        := lib$(NAME).dylib
endif

.PHONY: all clean check-header
all: $(SO)

$(SO): $(SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(LIBS)

# Syntax-only pass; useful in CI where linking against QEMU is not wanted.
check-header: $(SRC)
	$(CC) $(CFLAGS) -fsyntax-only $<

clean:
	rm -f $(SO) lib$(NAME).so lib$(NAME).dylib
