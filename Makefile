APP = main

# source files
SRCS = main.c rte_wg.c noise.c

# build directory
BUILDDIR = build

# object files in build dir
OBJS = $(SRCS:%.c=$(BUILDDIR)/%.o)

CFLAGS += -O0 -g
CFLAGS += $(shell pkg-config --cflags libdpdk)
LDFLAGS += $(shell pkg-config --libs libdpdk libsodium libpcap libb2)

# default target
all: $(BUILDDIR)/$(APP)

# ensure build dir exists
$(BUILDDIR):
	mkdir -p $(BUILDDIR)

# link step
$(BUILDDIR)/$(APP): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

# compile step
$(BUILDDIR)/%.o: %.c | $(BUILDDIR)
	$(CC) $(CFLAGS) -c $< -o $@

# cleanup
clean:
	rm -rf $(BUILDDIR)