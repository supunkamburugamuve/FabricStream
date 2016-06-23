CC=g++
CFLAGS=-Wall -g -ggdb -std=gnu++11
LDFLAGS=-libverbs -pthread -L/N/u/skamburu/projects/fabbuild/fab/lib -lfabric
INC=-I/N/u/skamburu/projects/fabbuild/fab/include
main: main.o utils.o server.o
	$(CC) $(CFLAGS) main.o utils.o server.o -o main $(LDFLAGS)

main.o: main.cpp server.cpp utils.cpp 
	${CC} $(CFLAGS) $(INC) -c main.cpp server.cpp utils.cpp
server.o: utils.cpp server.cpp
	${CC} ${CFLAGS} $(INC) -c utils.cpp server.cpp	
utils.o: utils.cpp
	${CC} $(CFLAGS) $(INC) -c utils.cpp
