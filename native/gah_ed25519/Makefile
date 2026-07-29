EXTENSION = gah_ed25519
MODULE_big = gah_ed25519
OBJS = gah_ed25519.o
DATA = gah_ed25519--1.0.sql
PG_CONFIG ?= pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
SODIUM_CFLAGS ?= $(shell pkg-config --cflags libsodium 2>/dev/null)
SODIUM_LIBS ?= $(shell pkg-config --libs libsodium 2>/dev/null)

PG_CPPFLAGS += $(SODIUM_CFLAGS)
SHLIB_LINK += $(SODIUM_LIBS)

include $(PGXS)
