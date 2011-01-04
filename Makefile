TOOLS	=	readself pupunpack unself sceverify
TOOLS	+=	makeself norunpack puppack unpkg pkg
COMMON	=	tools.o aes.o sha1.o ec.o bn.o
DEPS	=	Makefile tools.h types.h

CC	=	gcc
CFLAGS	=	-g -O2 -Wall -W
LDFLAGS =	-lz

OBJS	= $(COMMON) $(addsuffix .o, $(TOOLS))

all: $(TOOLS)

$(TOOLS): %: %.o $(COMMON) $(DEPS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(COMMON) 

$(OBJS): %.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -f $(OBJS)
