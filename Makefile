CC=g++
CFLAGS=-Wall -g -ggdb
LDFLAGS= -libverbs -pthread

main: main.o utils.o server.o
	$(CC) $(CFLAGS) main.o utils.o server.o -o main $(LDFLAGS)

main.o: main.cpp 
	${CC} $(CFLAGS) -c main.cpp
server.o: utils.cpp server.cpp
    ${CC} ${CFLAGS} -c utils.cpp server.cpp	
utils.o: utils.cpp
	${CC} $(CFLAGS) -c utils.cpp
