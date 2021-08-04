# VPATH = /media/sf_Studium/Master/Masterthesis/prototyp/ebpf/
TARGET = benchmark
# LIBS = -lmrloop -luring -lzstd
LIBS = -luring -lbpf -lpthread
CC = g++
CFLAGS = -O3 -Wall

.PHONY: default all clean

default: $(TARGET)
all: default

debug: CFLAGS = -g -Wall
debug: all

OBJECTS = $(patsubst %.cc, %.o, $(wildcard *.cc))
HEADERS = $(wildcard *.h)

%.o: %.cc $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(CFLAGS) $(OBJECTS) $(LIBS) -o $@

clean:
	-rm -f *.o
	-rm -f $(TARGET)

