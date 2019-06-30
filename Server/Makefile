OBJS	= PresenceServer.o AuthServer.o Cryptography.o CurlWebRequest.o DataManager.o stdafx.o  Main.o

CC	= g++
C	= gcc
CFLAGS	= -g -Wall -Os -fno-strict-aliasing -lpthread -lcurl -fpermissive -lcrypto

all:	$(OBJS)
		$(CC) $(CFLAGS) $(OBJS) -o ../Server

PresenceServer.o:	PresenceServer.cc
		$(CC) $(CFLAGS) -c PresenceServer.cc -o PresenceServer.o
		
AuthServer.o:	AuthServer.cc
		$(CC) $(CFLAGS) -c AuthServer.cc -o AuthServer.o
		
Cryptography.o:	Cryptography.cc
		$(CC) $(CFLAGS) -c Cryptography.cc -o Cryptography.o
		
CurlWebRequest.o:	CurlWebRequest.cc
		$(CC) $(CFLAGS) -c CurlWebRequest.cc -o CurlWebRequest.o
		
DataManager.o:	DataManager.cc
		$(CC) $(CFLAGS) -c DataManager.cc -o DataManager.o
		
stdafx.o:	stdafx.cc
		$(CC) $(CFLAGS) -c stdafx.cc -o stdafx.o
		
Main.o:	Main.cc
		$(CC) $(CFLAGS) -c Main.cc -o Main.o
clean:
	rm -f *.o


