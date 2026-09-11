# ============================================================
# SYSSEC - System Security Tools for FreeBSD
# ============================================================

CC = cc
CFLAGS = -Wall -Wextra -O2 -I. -D__BSD_VISIBLE=1
LDFLAGS = -lm

SRCS = syssec.c parser.c
OBJS = $(SRCS:.c=.o)
TARGET = syssec

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $(OBJS) $(LDFLAGS)

%.o: %.c syssec.h parser.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

install: $(TARGET)
	mkdir -p /usr/local/sbin
	cp $(TARGET) /usr/local/sbin/
	chmod 755 /usr/local/sbin/$(TARGET)

uninstall:
	rm -f /usr/local/sbin/$(TARGET)

.PHONY: all clean install uninstall
