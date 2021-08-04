# VPATH = /media/sf_Studium/Master/Masterthesis/prototyp/ebpf/
TARGET = benchmark
# LIBS = -lmrloop -luring -lzstd
LIBS = -luring -lbpf -lelf -lz
CC = gcc
CFLAGS = -O2 -Wall

.PHONY: default all clean

default: $(TARGET)
all: default

debug: CFLAGS = -g -Wall
debug: all

OBJECTS = $(patsubst %.c, %.o, $(wildcard *.c))
HEADERS = $(wildcard *.h)

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)

