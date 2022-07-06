MY_CPPFLAGS := $(CPPFLAGS)
MY_CFLAGS := -Wall -Wextra -Werror $(CFLAGS)
MY_LDFLAGS := $(LDFLAGS)
CHECK := sparse
CHECKFLAGS := -D__linux__ -Dlinux -D__STDC__ -Dunix -D__unix__ \
	      -Wbitwise -Wno-return-void -Wno-unknown-attribute $(CF)

ifeq ($(C),1)
REAL_CC := $(CC)
CC := cgcc
export REAL_CC
endif

prefix ?= /usr/local
exec_prefix ?= ${prefix}
bindir ?= ${exec_prefix}/bin
INSTALL ?= install

src := killswitch.o

objs := $(addprefix src/, $(src))
deps := $(patsubst %.o, %.d, $(objs))

TARGET := killswitch

all: $(TARGET)

# include all .d files
-include $(deps)

$(TARGET): $(objs)
	$(CC) $^ -o $@ $(MY_LDFLAGS)

%.o: %.c
	$(CC) $(MY_CPPFLAGS) $(MY_CFLAGS) -MMD -c $< -o $@
ifeq ($(C),1)
	$(CHECK) $(CHECKFLAGS) $(MY_CPPFLAGS) $(MY_CFLAGS) $<
endif

clean:
	rm -f $(objs) $(deps) $(TARGET)

install-binaries: $(TARGET)
	$(INSTALL) -m 0755 -D $(TARGET) $(DESTDIR)${bindir}/killswitch
	$(foreach symlink, $(symlinks), \
		ln -sf $(TARGET) $(DESTDIR)${bindir}/$(symlink);)

install: install-binaries
