TARGET = tcp-block
OBJS = main.o block.o ip.o mac.o send.o util.o
CC = g++
CFLAGS = -std=c99 -W -Wall
LIBS = -lm -lpcap

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $^ $(LIBS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -o $@ $< -c

clean:
	rm -f $(TARGET) $(OBJS)