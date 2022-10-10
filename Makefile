CC := gcc
LDFLAGS := -lssl -lcrypto
UNAME := $(shell uname)

ifeq ($(UNAME), Darwin)
CFLAGS := -I/usr/local/opt/openssl/include -L/usr/local/opt/openssl/lib
endif

<<<<<<< Updated upstream
all: homeserver
=======
all: ssl-client homeserver
>>>>>>> Stashed changes

homeserver: homeserver.o
	$(CC) $(CFLAGS) -o homeserver homeserver.o $(LDFLAGS)

homeserver.o: homeserver.c
	$(CC) $(CFLAGS) -c homeserver.c

clean:
<<<<<<< Updated upstream
	rm -f homeserver homeserver.o
=======
	rm -f homeserver homeserver.o 
>>>>>>> Stashed changes
