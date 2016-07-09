CC=g++
CFLAGS=-Wall -g -ggdb -std=gnu++11
LDFLAGS=-libverbs -lrt -pthread -L/N/u/skamburu/projects/fabbuild/fab/lib -lfabric 
INC=-I/N/u/skamburu/projects/fabbuild/fab/include
main: main.o utils.o server.o client.o sclient.o sserver.o connection.o
	$(CC) $(CFLAGS) main.o utils.o server.o client.o sclient.o sserver.o connection.o -o main $(LDFLAGS)

main.o: main.cpp server.cpp client.cpp utils.cpp sserver.cpp sclient.cpp connection.cpp buffer.cpp
	${CC} $(CFLAGS) $(INC) -c main.cpp server.cpp utils.cpp client.cpp sserver.cpp sclient.cpp connection.cpp buffer.cpp
sserver.o: utils.cpp sserver.cpp connection.cpp buffer.cpp
	${CC} ${CFLAGS} $(INC) -c utils.cpp sserver.cpp connection.cpp buffer.cpp	
sclient.o: utils.cpp sclient.cpp connection.cpp buffer.cpp
	${CC} ${CFLAGS} $(INC) -c utils.cpp sclient.cpp connection.cpp buffer.cpp		
server.o: utils.cpp server.cpp sserver.cpp connection.cpp buffer.cpp
	${CC} ${CFLAGS} $(INC) -c utils.cpp server.cpp sserver.cpp connection.cpp buffer.cpp	
client.o: utils.cpp client.cpp sclient.cpp connection.cpp buffer.cpp
	${CC} ${CFLAGS} $(INC) -c utils.cpp client.cpp sclient.cpp connection.cpp buffer.cpp	
connection.o: connection.cpp utils.cpp
	${CC} ${CFLAGS} $(INC) -c utils.cpp connection.cpp	 	 		
buffer.o: buffer.cpp utils.cpp
	${CC} ${CFLAGS} $(INC) -c utils.cpp buffer.cpp	
utils.o: utils.cpp
	${CC} $(CFLAGS) $(INC) -c utils.cpp
clean:
	rm *.o main
