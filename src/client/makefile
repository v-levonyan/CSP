IDIR=../../headers
CC=gcc
CFLAGS=-I$(IDIR)

ODIR=obj
LDIR = ../lib

#LIBS=-lpthread

_DEPS = client.h
DEPS= $(patsubst %, $(IDIR)/%, $(_DEPS))

_OBJ = client.o client_main.o
OBJ = $(patsubst %, $(ODIR)/%, $(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

client_start: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~
