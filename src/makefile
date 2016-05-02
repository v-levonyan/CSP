IDIR=../headers
CC=gcc
CFLAGS=-I$(IDIR)

ODIR=obj
LDIR = ../lib

#LIBS=-lpthread

_DEPS = server.h
DEPS= $(patsubst %, $(IDIR)/%, $(_DEPS))

_OBJ = server_init.o server.o
OBJ = $(patsubst %, $(ODIR)/%, $(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

server_start: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~
