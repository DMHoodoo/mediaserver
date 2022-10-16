/******************************************************************************

PROGRAM:  homeserver.c
AUTHOR:   Hassan Khan & Dacia Pennington
COURSE:   CS469 - Distributed Systems (Regis University)
SYNOPSIS: Home media-server that forks a primary/backup process. Distributes
          media, verifies listings, and handles incoming client connections.
          Requires openssl
          sudo apt-get install openssl-dev


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
#include <openssl/conf.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/md5.h>
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

// Consts where arguments CAN be specified
// check for the space within the const!
#define RPC_REQUEST_LISTING "requestlisting"
#define RPC_REQUEST_FILE "requestfile "
#define RPC_REQUEST_MD5 "requestmd5 "
#define RPC_REQUEST_ISALIVE "ping"
#define RPC_DISCONNECT "disconnect"

#define SERVER_FAIL 1

#define ERR_RPC 2
#define INVALID_COMMAND 0
#define TOO_FEW_ARGS 1
#define TOO_MANY_ARGS 2
#define MALFORMED_REQUEST 3

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

int getMD5Sum(char* filename, unsigned char* md5Sum){
  MD5_CTX ctx;

  char md5Buffer[BUFFER_SIZE];

  ssize_t bytes;

  MD5_Init(&ctx);
  char fullFilePath[BUFFER_SIZE + strlen(filename) + strlen(DEFAULT_MEDIA_DIR) + 4];
  sprintf(fullFilePath, "./%s/%s", DEFAULT_MEDIA_DIR, filename);            

  int fileToRead, readStream, writeStream;

  fileToRead = open(fullFilePath, O_RDONLY, 644);

  if(fileToRead < 0){
    fprintf(stderr, "Server: Unable to process %s: %s\n", filename, strerror(errno));
    return errno;
  }

  bytes = read(fileToRead, md5Buffer, BUFFER_SIZE);

  while(bytes > 0){
    MD5_Update(&ctx, md5Buffer, bytes);
    bytes = read(fileToRead, md5Buffer, BUFFER_SIZE);
  }

  MD5_Final(md5Sum, &ctx);

  return 0;
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

  // Create the media dir if it doesn't exist
  struct stat dirStat;
  if (stat(DEFAULT_MEDIA_DIR, &dirStat) == -1) 
    mkdir(DEFAULT_MEDIA_DIR, 0744);
  

  homePID = getpid();
  mainPID = fork();
  
  if(getpid() == homePID)
    backupPID = fork();  

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

      // When we get a client connection, we create a new process to handle
      // it's communication
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

            printf("Waiting for client request..\n");

            // Read client request
            SSL_read(ssl, buffer, BUFFER_SIZE);

            // Command being issued
            char command[BUFFER_SIZE];

            // Argument of command
            char commandArg[BUFFER_SIZE];      

            // Dummy values for evaluating amount of arguments
            char dummy[BUFFER_SIZE];
            char dummy2[BUFFER_SIZE];

            // Buffer for sending replies to the client
            char serverReply[BUFFER_SIZE + 2];

            printf("Received \"%s\" from client\n", buffer);

            // We evaluate the MD5 hash of a requested file and send it back to the client
            // This is primarily used to determine if a file has changed on the server
            // so the client can update it if needs be.
            if(strncmp(buffer, RPC_REQUEST_MD5, strlen(RPC_REQUEST_MD5)) == 0){

              // This is the pattern %[^\"]
              // % indicates the start of something to look for
              // [] tells us to keep searching until X character
              // ^ is the NOT operator
              // We escape the double-quote character
              // So we're saying, keep reading until you reach a double-quote!
              if(sscanf(buffer, "%s \"%[^\"] %s %s", command, commandArg, dummy, dummy2) == 4){
                printf("Error: Too many arguments\n");

                // Marshal error parameters and send to client
                sprintf(serverReply, "%d %d\n", ERR_RPC, TOO_MANY_ARGS);
                SSL_write(ssl, serverReply, strlen(serverReply));

              }else if(sscanf(buffer, "%s \"%[^\"] %s", command, commandArg, dummy) != 3){
                printf("Error: Too few arguments\n");

                // Marshal error parameters and send to client
                sprintf(serverReply, "%d %d\n", ERR_RPC, TOO_FEW_ARGS);
                SSL_write(ssl, serverReply, strlen(serverReply));                   

              // There was a closing double-quote, but there are other characters attached
              }else if(sscanf(buffer, "%s \"%[^\"] %s", command, commandArg, dummy) == 3 && strcmp(dummy, "\"") != 0){
                printf("Error: Malformed request\n", dummy);

                // Marshal error parameters and send to client
                sprintf(serverReply, "%d %d\n", ERR_RPC, MALFORMED_REQUEST);
                SSL_write(ssl, serverReply, strlen(serverReply));                   
              } else if(sscanf(buffer, "%s \"%[^\"] %s", command, commandArg, dummy) == 3){
                printf("Sending MD5 to client\n");
                
                unsigned char md5Sum[MD5_DIGEST_LENGTH];
                char md5String[MD5_DIGEST_LENGTH + 1];  

                int err = getMD5Sum(commandArg, md5Sum);

                if(err != 0){
                  sprintf(serverReply, "%d %d\n", SERVER_FAIL, errno);

                  SSL_write(ssl, serverReply, strlen(serverReply));
                } else{

                  // Was getting junk data in the first 4 bytes without this
                  md5String[0] = '\0';
                  
                  int i;
                  // Load the md5sum into a string buffer and send it to the client
                  for(i = 0; i < MD5_DIGEST_LENGTH; i++){
                    sprintf(buffer, "%02x", md5Sum[i]);
                    strncat(md5String, buffer, strlen(buffer));
                  }

                  SSL_write(ssl, md5String, strlen(md5String));

                  printf("Printing new line\n");
                  // Newline to conform to the readLine Java standard
                  SSL_write(ssl, "\n", strlen("\n"));
                }
              }
            // If the client requests a disconnect, properly cleanup, close, and return the forked process
            // Also checks for '\0' which also indicates the client has ceased connection
            }else if(strcmp(buffer, RPC_DISCONNECT) == 0 || buffer[0] == '\0'){

              if(sscanf(buffer, "%s %s", command, dummy) == 2){
                printf("Too many arguments\n");

                // Marshal error parameters and send to client
                sprintf(serverReply, "%d %d\n", ERR_RPC, TOO_MANY_ARGS);
                SSL_write(ssl, serverReply, strlen(serverReply)); 

              } else if(sscanf(buffer, "%s", command) == 1 || buffer[0] == '\0'){
                // Terminate the SSL session, close the TCP connection, and clean up
                printf("%d: Server: Terminating SSL session and TCP connection with client (%s)\n",
                  getpid(), client_addr);
                SSL_free(ssl);
                close(client);

                return EXIT_SUCCESS;
              }

            // If the client requests if the connection is still alive, send back a pong
            } else if(strncmp(buffer, RPC_REQUEST_ISALIVE, strlen(RPC_REQUEST_ISALIVE)) == 0){   

              if(sscanf(buffer, "%s %s", command, dummy) == 2){
                printf("Too many arguments\n");

                // Marshal error parameters and send to client
                sprintf(serverReply, "%d %d\n", ERR_RPC, TOO_MANY_ARGS);
                SSL_write(ssl, serverReply, strlen(serverReply));    

              } else if(sscanf(buffer, "%s", command) && strcmp(command, RPC_REQUEST_ISALIVE) != 0){
                printf("Invalid command %s\n", command);

                // Marshal error parameters and send to client
                sprintf(serverReply, "%d %d\n", ERR_RPC, INVALID_COMMAND);
                SSL_write(ssl, serverReply, strlen(serverReply));           

              } else if(sscanf(buffer, "%s", command) == 1){
                sprintf(serverReply, "%s\n", "pong");
                SSL_write(ssl, serverReply, strlen(serverReply) + 1);
              }
            // If the user requested the list of the directory
            }else if(strncmp(buffer, RPC_REQUEST_LISTING, strlen(RPC_REQUEST_LISTING)) == 0){

              if(sscanf(buffer, "%s %s", command, dummy) == 2){
                printf("Too many arguments\n");

                // Marshal error parameters and send to client
                sprintf(serverReply, "%d %d\n", ERR_RPC, TOO_MANY_ARGS);
                SSL_write(ssl, serverReply, strlen(serverReply));    

              // Make sure the command is actually as stated and isn't like requestlistingabcd
              } else if(sscanf(buffer, "%s", command) && strcmp(command, RPC_REQUEST_LISTING) != 0){
                printf("Invalid command %s\n", command);

                // Marshal error parameters and send to client
                sprintf(serverReply, "%d %d\n", ERR_RPC, INVALID_COMMAND);
                SSL_write(ssl, serverReply, strlen(serverReply));    
              } else if(sscanf(buffer, "%s", command) == 1){

                // Marshal parameters and let the client know we are about to
                // start reading the list
                sprintf(serverReply, "%d %d\n", RPC_SUCCESS, RPC_SUCCESS);
                SSL_write(ssl, serverReply, strlen(serverReply));    
                
                printf("%d: Sending list to client..\n", getpid());
                DIR *directory;

                struct dirent *dir;

                directory = opendir(DEFAULT_MEDIA_DIR);

                if(directory) {
                  while((dir = readdir(directory)) != NULL) {
                    sprintf(serverReply, "%s\n", dir->d_name);

                    if(strcmp(dir->d_name, ".") != 0 && strcmp(dir->d_name, "..") != 0)
                      SSL_write(ssl, serverReply, strlen(serverReply) + 1);                  
                  }         

                  sprintf(serverReply, "%d\n", RPC_SUCCESS);     

                  SSL_write(ssl, serverReply, strlen(serverReply) + 1);
                  closedir(directory);

                  printf("Finished writing list to client...\n");                
                }
              }
            } else if(strncmp(buffer, RPC_REQUEST_FILE, strlen(RPC_REQUEST_FILE)) == 0){

              // This is the pattern %[^\"]
              // % indicates the start of something to look for
              // [] tells us to keep searching until X character
              // ^ is the NOT operator
              // We escape the double-quote character
              // So we're saying, keep reading until you reach a double-quote!
              if(sscanf(buffer, "%s \"%[^\"] %s %s", command, commandArg, dummy, dummy2) == 4){
                printf("Error: Too many arguments.\n");

                // Marshal error parameters and send to client
                sprintf(serverReply, "%d %d\n", ERR_RPC, TOO_MANY_ARGS);
                SSL_write(ssl, serverReply, strlen(serverReply));                 

              }else if(sscanf(buffer, "%s \"%[^\"] %s", command, commandArg, dummy) != 3){
                printf("Error: Too few arguments\n");

                // Marshal error parameters and send to client
                sprintf(serverReply, "%d %d\n", ERR_RPC, TOO_FEW_ARGS);
                SSL_write(ssl, serverReply, strlen(serverReply));                   

              }else if(sscanf(buffer, "%s \"%[^\"] %s", command, commandArg, dummy) == 3 && strcmp(dummy, "\"") != 0){
                printf("Error: Malformed request\n");

                // Marshal error parameters and send to client
                sprintf(serverReply, "%d %d\n", ERR_RPC, MALFORMED_REQUEST);
                SSL_write(ssl, serverReply, strlen(serverReply));                   

              } else if(sscanf(buffer, "%s \"%[^\"] %s", command, commandArg, dummy) == 3){
                printf("%d: Sending file \"%s\" to client.\n", getpid(), commandArg);

                char fullFilePath[BUFFER_SIZE + sizeof(commandArg) + strlen(DEFAULT_MEDIA_DIR) + 4];

                sprintf(fullFilePath, "./%s/%s", DEFAULT_MEDIA_DIR, commandArg);            

                int fileToRead, readStream, writeStream;

                fileToRead = open(fullFilePath, O_RDONLY, 644);

                if(fileToRead < 0){
                  fprintf(stderr, "Server: Unable to process %s: %s\n", commandArg, strerror(errno));

                  // Marshal error parameters and send to client
                  sprintf(serverReply, "%d %d\n", SERVER_FAIL, errno);
                  SSL_write(ssl, serverReply, strlen(serverReply));                     
                }

                // Send a response to the client that the file sent is
                // valid and that we can start writing immediately
                sprintf(serverReply, "%d %d\n", RPC_SUCCESS, START_WRITING);

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

                // While we still have chunks to read...
                do{
                  readStream = read(fileToRead, fileBuffer, BUFFER_SIZE);

                  if(readStream < 0){
                    fprintf(stderr, "Error: Failed to read %s: %s\n", commandArg, strerror(errno));
                    break;
                  }

                  // Write the contents of buffer from the readstream to the client socket
                  writeStream = SSL_write(ssl, fileBuffer, readStream);

                }while(readStream > 0);

                close(readStream);
                close(writeStream);
                close(fileToRead);

                printf("%d: Finished writing \"%s\" to client.\n", getpid(), commandArg);
                SSL_write(ssl, "\n", strlen("\n"));
              }

            } else {
              // Load the command so we can print an error
              sscanf(buffer, "%s", command);
              printf("%d: Invalid command issued '%s'\n", getpid(), command);

              // Marshal error parameters and send to client
              sprintf(serverReply, "%d %d\n", ERR_RPC, INVALID_COMMAND);
              SSL_write(ssl, serverReply, strlen(serverReply));    
            }

            bzero(buffer, BUFFER_SIZE);
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