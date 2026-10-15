CC = g++
CFLAGS = -std=c++11 -Wall -Wextra -pthread
TARGETS = client server

all: $(TARGETS)

client: client.cpp
	$(CC) $(CFLAGS) -o client client.cpp

server: server.cpp
	$(CC) $(CFLAGS) -o server server.cpp

clean:
	rm -f $(TARGETS)

.PHONY: all clean
