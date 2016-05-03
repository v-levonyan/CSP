IDIR=.
CC=gcc
CFLAGS=-I$(IDIR)

ODIR=obj
LDIR = ../lib

LIBS=-lpthread

_DEPS = thread_pool.h
DEPS= $(patsubst %, $(IDIR)/%, $(_DEPS))

_OBJ = testpool.o  thread_pool.o
OBJ = $(patsubst %, $(ODIR)/%, $(_OBJ))

$(ODIR)/%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

test_pool: $(OBJ)
	gcc -o $@ $^ $(CFLAGS) $(LIBS)

.PHONY: clean

clean:
	rm -f $(ODIR)/*.o *~ core $(INCDIR)/*~
