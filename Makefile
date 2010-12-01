TOOLS	=	readself pupunpack unself unpkg
COMMON	=	tools.o aes.o
DEPS	=	Makefile tools.h types.h

CC	=	gcc
CFLAGS	=	-g -O0 -Wall -W -Wextra
LDFLAGS =	-lz

OBJS	= $(COMMON) $(addsuffix .o, $(TOOLS))

all: $(TOOLS)

$(TOOLS): %: %.o $(COMMON) $(DEPS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(COMMON) 

$(OBJS): %.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -f $(OBJS)
