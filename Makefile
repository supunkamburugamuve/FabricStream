CC=g++
CFLAGS=-Wall -g -ggdb
LDFLAGS= -libverbs -pthread

main: main.o utils.o
	$(CC) $(CFLAGS) main.o utils.o -o main $(LDFLAGS)

main.o: main.cpp
	${CC} $(CFLAGS) -c main.cpp
utils.o: utils.cpp
	${CC} $(CFLAGS) -c utils.cpp
