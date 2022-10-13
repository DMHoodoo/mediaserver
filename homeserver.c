/******************************************************************************

PROGRAM:  ssl-server.c
AUTHOR:   Hassan Khan
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: This program is a small server application that receives incoming TCP
          connections from clients and transfers a requested file from the
          server to the client.  It uses a secure SSL/TLS connection using
          a certificate generated with the openssl application.

          To create a self-signed certificate your server can use, at the
          command prompt type:

          openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out cert.pem

          This will create two files: a private key contained in the file
          'key.pem' and a certificate containing a public key in the file
          'cert.pem'. Your server will require both in order to operate
          properly. These files are not needed by the client.

          Some of the code and descriptions can be found in "Network Security
          with OpenSSL", O'Reilly Media, 2002.

******************************************************************************/
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <signal.h>
#include <dirent.h>

#define BUFFER_SIZE       256
#define DEFAULT_PORT      4433
#define CERTIFICATE_FILE  "cert.pem"
#define KEY_FILE          "key.pem"
#define DEFAULT_MEDIA_DIR "media"

#define DEFAULT_PORT_MAIN 4433
#define DEFAULT_PORT_BACKUP 4434

// Error and sub-codes (Where relevant)
#define RPC_SUCCESS 0
#define START_WRITING 0
#define FINISHED_WRITING 1

#define RPC_REQUEST_LISTING "requestlisting"
#define RPC_REQUEST_FILE "requestfile "
#define RPC_REQUEST_MD5 "requestmd5 "
#define RPC_REQUEST_ISALIVE "ping"
#define RPC_DISCONNECT "disconnect "

#define SERVER_FAIL 1

#define ERR_RPC 2
#define INVALID_COMMAND 0
#define TOO_FEW_ARGS 1
#define TOO_MANY_ARGS 2

/******************************************************************************

This function does the basic necessary housekeeping to establish TCP connections
to the server.  It first creates a new socket, binds the network interface of
the machine to that socket, then listens on the socket for incoming TCP
connections.

*******************************************************************************/
int create_socket(unsigned int port) {
  int    s;
  struct sockaddr_in addr;

  // First we set up a network socket. An IP socket address is a combination
  // of an IP interface address plus a 16-bit port number. The struct field
  // sin_family is *always* set to AF_INET. Anything else returns an error.
  // The TCP port is stored in sin_port, but needs to be converted to the
  // format on the host machine to network byte order, which is why htons()
  // is called. Setting s_addr to INADDR_ANY binds the socket and listen on
  // any available network interface on the machine, so clients can connect
  // through any, e.g., external network interface, localhost, etc.

  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr.s_addr = htonl(INADDR_ANY);

  // Create a socket (endpoint) for network communication.  The socket()
  // call returns a socket descriptor, which works exactly like a file
  // descriptor for file system operations we worked with in CS431
  //
  // Sockets are by default blocking, so the server will block while reading
  // from or writing to a socket. For most applications this is acceptable.
  s = socket(AF_INET, SOCK_STREAM, 0);
  if (s < 0) {
    fprintf(stderr, "Server: Unable to create socket: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  // When you create a socket, it exists within a namespace, but does not have
  // a network address associated with it.  The bind system call creates the
  // association between the socket and the network interface.
  //
  // An error could result from an invalid socket descriptor, an address already
  // in use, or an invalid network address
  if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
    fprintf(stderr, "Server: Unable to bind to socket %d: %s\n", port, strerror(errno));
    exit(EXIT_FAILURE);
  }

  // Listen for incoming TCP connections using the newly created and configured
  // socket. The second argument (1) indicates the number of pending connections
  // allowed, which in this case is one.  That means if the server is connected
  // to one client, a second client attempting to connect may receive an error,
  // e.g., connection refused.
  //
  // Failure could result from an invalid socket descriptor or from using a
  // socket descriptor that is already in use.
  if (listen(s, 1) < 0) {
    fprintf(stderr, "Server: Unable to listen: %s", strerror(errno));
    exit(EXIT_FAILURE);
  }

  printf("Server: Listening on TCP port %u\n", port);

  return s;
}

/******************************************************************************

This function does some initialization of the OpenSSL library functions used in
this program.  The function SSL_load_error_strings registers the error strings
for all of the libssl and libcrypto functions so that appropriate textual error
messages are displayed when error conditions arise. OpenSSL_add_ssl_algorithms
registers the available SSL/TLS ciphers and digests used for encryption.

******************************************************************************/
void init_openssl() {
  SSL_load_error_strings();
  OpenSSL_add_ssl_algorithms();
}

/******************************************************************************

EVP_cleanup removes all of the SSL/TLS ciphers and digests registered earlier.

******************************************************************************/
void cleanup_openssl() {
  EVP_cleanup();
}

/******************************************************************************

An SSL_CTX object is an instance of a factory design pattern that produces SSL
connection objects, each called a context. A context is used to set parameters
for the connection, and in this program, each context is configured using the
configure_context() function below. Each context object is created using the
function SSL_CTX_new(), and the result of that call is what is returned by this
function and subsequently configured with connection information.

One other thing to point out is when creating a context, the SSL protocol must
be specified ahead of time using an instance of an SSL_method object.  In this
case, we are creating an instance of an SSLv23_server_method, which is an
SSL_METHOD object for an SSL/TLS server. Of the available types in the OpenSSL
library, this provides the most functionality.

******************************************************************************/
SSL_CTX* create_new_context() {
  const SSL_METHOD* ssl_method; // This should be declared 'const' to avoid
                                // getting a compiler warning about the call to
                                // SSLv23_server_method()
  SSL_CTX*          ssl_ctx;

  // Use SSL/TLS method for server
  ssl_method = SSLv23_server_method();

  // Create new context instance
  ssl_ctx = SSL_CTX_new(ssl_method);
  if (ssl_ctx == NULL) {
    fprintf(stderr, "Server: cannot create SSL context:\n");
    ERR_print_errors_fp(stderr);
    exit(EXIT_FAILURE);
  }

  return ssl_ctx;
}


/******************************************************************************

We will use Elliptic Curve Diffie Hellman anonymous key agreement protocol for
the session key shared between client and server.  We first configure the SSL
context to use that protocol by calling the function SSL_CTX_set_ecdh_auto().
The second argument (onoff) tells the function to automatically use the highest
preference curve (supported by both client and server) for the key agreement.

Note that for error conditions specific to SSL/TLS, the OpenSSL library does
not set the variable errno, so we must use the built-in error printing routines.

******************************************************************************/
void configure_context(SSL_CTX* ssl_ctx) {
  SSL_CTX_set_ecdh_auto(ssl_ctx, 1);

  // Set the certificate to use, i.e., 'cert.pem'
  if (SSL_CTX_use_certificate_file(ssl_ctx, CERTIFICATE_FILE, SSL_FILETYPE_PEM)
    <= 0) {
    fprintf(stderr, "Server: cannot set certificate:\n");
  ERR_print_errors_fp(stderr);
  exit(EXIT_FAILURE);
}

  // Set the private key contained in the key file, i.e., 'key.pem'
if (SSL_CTX_use_PrivateKey_file(ssl_ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
  fprintf(stderr, "Server: cannot set certificate:\n");
  ERR_print_errors_fp(stderr);
  exit(EXIT_FAILURE);
}
}

/******************************************************************************

The sequence of steps required to establish a secure SSL/TLS connection is:

1.  Initialize the SSL algorithms
2.  Create and configure an SSL context object
3.  Create a new network socket in the traditional way
4.  Listen for incoming connections
5.  Accept incoming connections as they arrive
6.  Create a new SSL object for the newly arrived connection
7.  Bind the SSL object to the network socket descriptor

Once these steps are completed successfully, use the functions SSL_read() and
SSL_write() to read from/write to the socket, but using the SSL object rather
then the socket descriptor.  Once the session is complete, free the memory
allocated to the SSL object and close the socket descriptor.

******************************************************************************/

int main(int argc, char **argv) {
  pid_t pid, homePID, mainPID, backupPID;
  SSL_CTX*     ssl_ctx;
  unsigned int sockfd;
  unsigned int port;
  char         buffer[BUFFER_SIZE];

  homePID = getpid();
  mainPID = fork();
  // printf("MainPID is %d\n", mainPID);
  if(getpid() == homePID)
    backupPID = fork();
    // printf("backupPID is %d\n", backupPID);
  

  pid = getpid();

  if(pid != homePID){
    // Initialize and create SSL data structures and algorithms
    init_openssl();
    ssl_ctx = create_new_context();
    configure_context(ssl_ctx);

    if(mainPID == 0){
      printf("%d: Assigning port %d\n", getpid(), DEFAULT_PORT_MAIN);

      // Port can be specified on the command line. If it's not, use default port
      switch(argc) {
        case 1:
        port = DEFAULT_PORT_MAIN;
        break;
        case 2:
        port = atoi(argv[1]);
        break;
        default:
        fprintf(stderr, "Usage: ssl-server <port> (optional)\n");
        exit(EXIT_FAILURE);
      }
    } else if(backupPID == 0) {
      printf("%d: Assigning port %d\n", getpid(), DEFAULT_PORT_BACKUP);
      port = DEFAULT_PORT_BACKUP;
    }


    // This will create a network socket and return a socket descriptor, which is
    // and works just like a file descriptor, but for network communcations. Note
    // we have to specify which TCP/UDP port on which we are communicating as an
    // argument to our user-defined create_socket() function.
    sockfd = create_socket(port);

    // Wait for incoming connections and handle them as the arrive
    while(true) {
      SSL*               ssl;
      int                client;
      int                readfd;
      int                rcount;
      const  char        reply[] = "Hello World!";
      struct sockaddr_in addr;
      unsigned int       len = sizeof(addr);
      char               client_addr[INET_ADDRSTRLEN];

      // Once an incoming connection arrives, accept it.  If this is successful,
      // we now have a connection between client and server and can communicate
      // using the socket descriptor
      client = accept(sockfd, (struct sockaddr*)&addr, &len);
      if (client < 0) {
        fprintf(stderr, "%d: Server: Unable to accept connection: %s\n",
         getpid(), strerror(errno));
        continue;
      }

      pid = fork();

      if(pid == 0){
        // Display the IPv4 network address of the connected client
        inet_ntop(AF_INET, (struct in_addr*)&addr.sin_addr, client_addr,
         INET_ADDRSTRLEN);
        printf("%d: Server: Established TCP connection with client (%s) on port %u\n",
          getpid(), client_addr, port);

        // Here we are creating a new SSL object to bind to the socket descriptor
        ssl = SSL_new(ssl_ctx);

        // Bind the SSL object to the network socket descriptor. The socket
        // descriptor will be used by OpenSSL to communicate with a client. This
        // function should only be called once the TCP connection is established.
        SSL_set_fd(ssl, client);

        // The last step in establishing a secure connection is calling SSL_accept(),
        // which executes the SSL/TLS handshake.  Because network sockets are
        // blocking by default, this function will block as well until the handshake
        // is complete.
        if (SSL_accept(ssl) <= 0) {
          fprintf(stderr, "Server: Could not establish secure connection:\n");
          ERR_print_errors_fp(stderr);
        } else {
          printf("%d: Server: Established SSL/TLS connection with client (%s)\n",
            getpid(), client_addr);

            // Keep the TCP connection alive until disconnected/killed
          while(true){
            fflush(stdout);

            // Read client request
            SSL_read(ssl, buffer, BUFFER_SIZE);

            // Command being issued
            char command[BUFFER_SIZE];

            // Argument of command
            char commandArg[BUFFER_SIZE];      

            // Dummy value for evaluating amount of arguments
            char dummy[BUFFER_SIZE];

            // Buffer for sending replies to the client
            char serverReply[BUFFER_SIZE + 2];

            // If the client requests a disconnect, properly cleanup, close, and return the forked process
            if(strncmp(buffer, RPC_DISCONNECT, strlen(RPC_DISCONNECT)) == 0){

              // Terminate the SSL session, close the TCP connection, and clean up
              printf("%d: Server: Terminating SSL session and TCP connection with client (%s)\n",
                getpid(), client_addr);
              SSL_free(ssl);
              close(client);

              return EXIT_SUCCESS;

            // If the client requests if the connection is still alive, send back a pong
            } else if(strncmp(buffer, RPC_REQUEST_ISALIVE, strlen(RPC_REQUEST_ISALIVE)) == 0){            

              sprintf(serverReply, "%s", "pong\n");
              SSL_write(ssl, serverReply, strlen(serverReply));

            // If the user requested the list of the directory
            }else if(strncmp(buffer, RPC_REQUEST_LISTING, strlen(RPC_REQUEST_LISTING)) == 0){

              printf("%d: Sending list to client..\n", getpid());
              DIR *directory;

              struct dirent *dir;

              directory = opendir(DEFAULT_MEDIA_DIR);

              if(directory) {
                while((dir = readdir(directory)) != NULL) {
                  sprintf(serverReply, "%s\n", dir->d_name);

                  if(strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0){
                    int tempWriteStream;

                    tempWriteStream = SSL_write(ssl, serverReply, strlen(serverReply) + 1);   

                    // If there was a failure to write to the socket..
                    if(tempWriteStream < 0){
                      fprintf(stderr, "Server: Unable to process: %s\n", strerror(errno));

                      // Marshal error parameters and send to client: TODO THIS
                      // sprintf(serverReply, "%d %d", SERVER_FAIL, errno);
                      // SSL_write(ssl, serverReply, strlen(serverReply));  

                      close(tempWriteStream);
                    }
                  }                
                }         

                sprintf(serverReply, "%d\r\n", RPC_SUCCESS);     
                SSL_write(ssl, serverReply, strlen(serverReply) + 1);
                closedir(directory);
              }
            } else if(strncmp(buffer, RPC_REQUEST_FILE, strlen(RPC_REQUEST_FILE)) == 0){

              // This is the pattern %[^\"]
              // % indicates the start of something to look for
              // [] tells us to keep searching until X character
              // ^ is the NOT operator
              // We escape the double-quote character
              // So we're saying, keep reading until you reach a double-quote!
              sscanf(buffer, "%s \"%[^\"]", command, commandArg);

              printf("%d: Attempting to send file \"%s\" to client.\n", getpid(), commandArg);

              char fullFilePath[BUFFER_SIZE + sizeof(commandArg) + strlen(DEFAULT_MEDIA_DIR) + 4];

              sprintf(fullFilePath, "./%s/%s", DEFAULT_MEDIA_DIR, commandArg);            

              int fileToRead, readStream, writeStream;

              fileToRead = open(fullFilePath, O_RDONLY, 644);

              if(fileToRead < 0)
                fprintf(stderr, "Server: Unable to process %s: %s\n", commandArg, strerror(errno));

              // Send a response to the client that the file sent is
              // valid and that we can start writing immediately
              sprintf(serverReply, "%d %d", RPC_SUCCESS, START_WRITING);              
              // sprintf(commandArg, "%s\n", commandArg);

              struct stat fileStats;
              off_t fileSize;
              stat(fullFilePath, &fileStats);


        		  //DP: sending file size first, recieved with buffered reader
              fileSize = fileStats.st_size;
              printf("File Size = %ld\n", fileSize);
              char size[BUFFER_SIZE];
              sprintf(size, "%ld\n", fileSize);

              SSL_write(ssl,size, BUFFER_SIZE);
    				  //DP: End of what I did here

              char fileBuffer[BUFFER_SIZE];

              int total = 0;


              // If writing to the socket fails at any point,
              // we terminate the read and notify the client
              // by setting writeChunkSuccess to 1
              int writeChunkSuccess = 0;

              // While we still have chunks to read...
              do{
                readStream = read(fileToRead, fileBuffer, BUFFER_SIZE);
                total += readStream;

                // Write the contents of buffer from the readstream to the client socket
                writeStream = SSL_write(ssl, fileBuffer, readStream);

                // If there was a failure to write to the socket..
                if(writeStream < 0){

                  // Notify client and end read/write loop by setting
                  // writeChunkSuccess to 1
                  fprintf(stderr, "Server: Unable to process %s: %s\n", commandArg, strerror(errno));

                  // Marshal error parameters and send to client
                  sprintf(serverReply, "%d %d", SERVER_FAIL, errno);
                  SSL_write(ssl, serverReply, strlen(serverReply));  

                  close(readStream);
                  close(writeStream);
                  close(fileToRead);

                  writeChunkSuccess = 1;
                  return -1;
                }                

              }while(readStream > 0);

              close(readStream);
              close(writeStream);
              close(fileToRead);

              printf("%d: Finished writing \"%s\" to client.\n", getpid(), commandArg);
              SSL_write(ssl, "\n", strlen("\n"));

              SSL_write(ssl, "FOE\n", strlen("FOE\n"));

            } else {
              printf("Invalid command issued %s\n", buffer);
            }
          }
        }
      }
    }

    // Tear down and clean up server data structures before terminating
    SSL_CTX_free(ssl_ctx);
    cleanup_openssl();
    close(sockfd);

    return EXIT_SUCCESS;  
  } else {
    printf("%d : Main-process forked %d and %d succesfully\n", pid, mainPID, backupPID);
  }
}