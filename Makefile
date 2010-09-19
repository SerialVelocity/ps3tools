TOOLS	=	readself pupunpack
COMMON	=	tools.o
DEPS	=	Makefile tools.h types.h

CC	=	gcc
CFLAGS	=	-g -W -Wall -Wextra
LDFLAGS =

OBJS	= $(COMMON) $(addsuffix .o, $(TOOLS))

all: $(TOOLS)

$(TOOLS): %: %.o $(COMMON) $(DEPS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $< $(COMMON) 

$(OBJS): %.o: %.c $(DEPS)
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	-rm -f $(OBJS)
