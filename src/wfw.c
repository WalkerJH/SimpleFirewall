#include "conf.h"
#include "hash.h"
#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet6/in6.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/* Constants */
#define STR1(x)   #x
#define STR(x)    STR1(x)
#define DEVICE    "device"
#define PORT      "port"
#define BROADCAST "broadcast"
#define ANYIF     "0.0.0.0"
#define ANYPORT   "0"
#define PID       "pidfile"


/* Globals  */
static char* conffile   = STR(SYSCONFDIR) "/wfw.cfg";
static bool  printusage = false;


/* Prototypes */

/* Parse Options
 * argc, argv   The command line
 * returns      true iff the command line is successfully parsed
 *
 * This function sets the otherwise immutable global variables (above).  
 */
static
bool parseoptions(int argc, char* argv[]);

/* Usage
 * cmd   The name by which this program was invoked
 * file  The steam to which the usage statement is printed
 *
 * This function prints the simple usage statement.  This is typically invoked
 * if the user provides -h on the command line or the options don't parse.  
 */
static
void usage(char* cmd, FILE* file);

/* Ensure Tap
 * path     The full path to the tap device.
 * returns  If this function returns, it is the file descriptor for the tap
 *          device. 
 * 
 * This function tires to open the specified device for reading and writing.  If
 * that open fails, this function will report the error to stderr and exit the
 * program.   
 */
static
int  ensuretap(char* path);

/* Ensure Socket
 * localaddress   The IPv4 address to bind this socket to.
 * port           The port number to bind this socket to.
 *
 * This function creates a bound socket.  Notice that both the local address and
 * the port number are strings.  
 */
static
int ensuresocket(char* localaddr, char* port);

/* Make Socket Address
 * address, port  The string representation of an IPv4 socket address.
 *
 * This is a convince routine to convert an address-port pair to an IPv4 socket
 * address.  
 */
static
struct sockaddr_in makesockaddr(char* address, char* port);

/* mkfdset
 * set    The fd_set to populate
 * ...    A list of file descriptors terminated with a zero.
 *
 * This function will clear the fd_set then populate it with the specified file
 * descriptors.  
 */
static
int mkfdset(fd_set* set, ...);

/* Bridge 
 * tap     The local tap device
 * in      The network socket that receives broadcast packets.
 * out     The network socket on which to send broadcast packets.
 * bcaddr  The broadcast address for the virtual ethernet link.
 *
 * This is the main loop for wfw.  Data from the tap is broadcast on the
 * socket.  Data broadcast on the socket is written to the tap.  
 */
static
void bridge(int tap, int in, int out, struct sockaddr_in bcaddr);

/* addresscmp
 *
 * Comparison function for two MAC addresses
 */
static
int addresscmp (void* addr1, void* addr2);

/* tcpcmp
 *
 * Comparison function for two tcp server info structs
 */
static
int tcpcmp (void* tcp1, void* tcp2);

/* freepair
 *
 * Free a key value pair in the hash table
 */
static
void freepair (void* key, void* val);

/* Main
 * 
 * Mostly, main parses the command line, the conf file, creates the necessary
 * structures and then calls bridge.  Bridge is where the real work is done. 
 */
int main(int argc, char* argv[]) {
  int result = EXIT_SUCCESS;

  if(!parseoptions(argc, argv)) {
    usage(argv[0], stderr);
    result = EXIT_FAILURE;
  }
  else if(printusage) {
    usage(argv[0], stdout);
  }
  else {
    hashtable conf = readconf (conffile);
    int       tap  = ensuretap (htstrfind (conf, DEVICE));
    int       out  = ensuresocket(ANYIF, ANYPORT);
    int       in   = ensuresocket(htstrfind (conf, BROADCAST),
                                  htstrfind (conf, PORT));
    struct sockaddr_in
      bcaddr       = makesockaddr (htstrfind (conf,BROADCAST),
                                   htstrfind (conf, PORT));

    daemon(0,0);
    if (hthasstrkey(conf, PID)) {
	    FILE *pidfile = fopen(htstrfind(conf, PID), "w");
	    if (pidfile != NULL) {
		    fprintf(pidfile, "%d\n", getpid());
		    fclose(pidfile);
	    }
    }

    bridge(tap, in, out, bcaddr);
    
    close(in);
    close(out);
    close(tap);
    htfree(conf);
  }

  return result;
}



/* Parse Options
 *
 * see man 3 getopt
 */
static
bool parseoptions(int argc, char* argv[]) {
  static const char* OPTS = "hc:";

  bool parsed = true;

  char c = getopt(argc, argv, OPTS);
  while(c != -1) {
    switch (c) {
    case 'c':
      conffile = optarg;
      break;
        
    case 'h':
      printusage = true;
      break;

    case '?':
      parsed = false;
      break;
    }

    c = parsed ? getopt(argc, argv, OPTS) : -1;
  }

  if(parsed) {
    argc -= optind;
    argv += optind;
  }

  return parsed;
}

/* Print Usage Statement
 *
 */

static
void usage(char* cmd, FILE* file) {
  fprintf(file, "Usage: %s -c file.cfg [-h]\n", cmd);
}

/* Ensure Tap device is open.
 *
 */
static
int ensuretap(char* path) {
  int fd = open(path, O_RDWR | O_NOSIGPIPE);
  if(-1 == fd) {
    perror("open");
    fprintf(stderr, "Failed to open device %s\n", path);
    exit(EXIT_FAILURE);
  }
  return fd;
}

/* Ensure socket
 *
 * Note the use of atoi, htons, and inet_pton. 
 */
static
int ensuresocket(char* localaddr, char* port) {
  int sock = socket(PF_INET, SOCK_DGRAM, 0);
  if(-1 == sock) {
    perror("socket");
    exit (EXIT_FAILURE);
  }

  int bcast = 1;
  if (-1 == setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
                       &bcast, sizeof(bcast))) {
    perror("setsockopt(broadcast)");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in addr = makesockaddr(localaddr, port);
  if(0 != bind(sock, (struct sockaddr*)&addr, sizeof(addr))) {
    perror("bind");
    char buf[80];
    fprintf(stderr,
            "failed to bind to %s\n",
            inet_ntop(AF_INET, &(addr.sin_addr), buf, 80));
    exit(EXIT_FAILURE);
  }

  return sock;  
}

/* Make Sock Addr
 * 
 * Note the use of inet_pton and htons.
 */
static
struct sockaddr_in makesockaddr(char* address, char* port) {
  struct sockaddr_in addr;
  bzero(&addr, sizeof(addr));
  addr.sin_len    = sizeof(addr);
  addr.sin_family = AF_INET;
  addr.sin_port   = htons(atoi(port));
  inet_pton(AF_INET, address, &(addr.sin_addr));

  return addr;
}

/* mkfdset
 *
 * Note the use of va_list, va_arg, and va_end. 
 */
static
int mkfdset(fd_set* set, ...) {
  int max = 0;
  
  FD_ZERO(set);
  
  va_list ap;
  va_start(ap, set);
  int s = va_arg(ap, int);
  while(s != 0) {
    if(s > max)
      max = s;
    FD_SET(s, set);
    s = va_arg(ap, int);
  }
  va_end(ap);
  
  return max;
}

/* Bridge
 * 
 * Note the use of select, sendto, and recvfrom.  
 */
static
void bridge(int tap, int in, int out, struct sockaddr_in bcaddr) {
#define BUFSZ 1514
#define MAX_CONNECTED_DEVICES 64

	fd_set rdset;

	int maxfd = mkfdset(&rdset, tap, in, out, 0);

	struct ethernet_frame_t {
		char dst[6];
		char src[6];
		uint16_t type;
		char payload[1500];
	};

	struct ipv6_packet_t {
		int version: 4,
				traffic_class: 8,
				flow_label: 20;
		uint16_t payload_length;
		char next_header;
		char hop_limit;
		char source_address[16];
		char destination_address[16];
		char headers[];
	};
	enum header_signifiers {
		NEXT_TCP = 0x6,
		NEXT_UDP = 0x11,
	};

	struct tcp_segment_t {
		uint16_t source_port;
		uint16_t destination_port;
		uint32_t sequence_number;
		uint32_t ack_number;
		int padding0: 4,
				header_size: 4,
				FIN: 1,
				SYN: 1,
				RST: 1,
				PSH: 1,
				ACK: 1,
				URG: 1,
				padding1: 2;
		uint16_t receive_window;
		uint16_t checksum;
		char options[];
	};

	struct saved_tcp {
		uint16_t local_port;
		uint16_t remote_port;
		char remote_address[16];
	};

	hashtable known_addresses = htnew( MAX_CONNECTED_DEVICES, addresscmp, freepair);
	hashtable known_tcp_servers = htnew( MAX_CONNECTED_DEVICES, addresscmp, freepair);

	// Loop to receive incoming frames and decide what to do with them
	while (0 <= select(1 + maxfd, &rdset, NULL, NULL, NULL)) {

		// Tap
		if (FD_ISSET(tap, &rdset)) {
			struct ethernet_frame_t *current_frame  = malloc(sizeof(struct ethernet_frame_t));
			ssize_t rdct = read(tap, (void*) current_frame, BUFSZ);
			if (rdct < 0) {
				perror("read");
			} else {
				struct ipv6_packet_t *current_packet = (ipv6_packet_t *)current_frame->payload;
				if (current_packet->next_header == NEXT_TCP) {
					struct tcp_segment_t *current_segment = (tcp_segment_t *)current_packet->headers;
					if (current_segment->SYN == 1) {
						struct saved_tcp *new_tcp = malloc(sizeof(struct saved_tcp));
						saved_tcp->local_port = current_segment->source_port;
						saved_tcp->remote_port = current_segment->destination_port;
						saved_tcp->remote_address = current_packet->destination_address;
					}
				}

				struct sockaddr_in* socket;
				socket = &bcaddr;
				if (hthaskey(known_addresses, current_frame->dst, 6)) {
					socket = (struct sockaddr_in *)htfind(known_addresses, current_frame->dst, 6);
				}
				if (-1 == sendto(out, (void *) current_frame, rdct, 0, (struct sockaddr *)socket, sizeof(*socket))) {
					perror("sendto");
				}
			}
		}

		// In
		else if (FD_ISSET(in, &rdset)) {
			struct sockaddr_in from;
			struct ethernet_frame_t *current_frame = malloc(sizeof(struct ethernet_frame_t));
			socklen_t flen = sizeof(from);
			ssize_t rdct = recvfrom(in, (void*) current_frame, BUFSZ, 0, (struct sockaddr *) &from, &flen);
			if (rdct < 0) {
				perror("recvfrom");
			} else if (-1 == write(tap, (void*) current_frame, rdct)) {
				perror("write");
			}

			if (false == htinsert(known_addresses, current_frame->src, 6, (void *) &from)) {
				perror("htinsert");
			}
		}

		// Out
		else if (FD_ISSET(out, &rdset)) {
			struct sockaddr_in from;
			struct ethernet_frame_t *current_frame = malloc(sizeof(struct ethernet_frame_t));
			socklen_t flen = sizeof(from);
			ssize_t rdct = recvfrom(out, (void*) current_frame, BUFSZ, 0, (struct sockaddr *) &from, &flen);
			if (rdct < 0) {
				perror("recvfrom");
			} else if (-1 == write(out, (void*) current_frame, rdct)) {
				perror("write");
			}

			if (false == htinsert(known_addresses, current_frame->src, 6, (void *) &from)) {
				perror("htinsert");
			}
		}

		maxfd = mkfdset(&rdset, tap, in, out, 0);
	}

	htfree(known_addresses);
}

/* addresscmp
 *
 * Comparison function for two MAC addresses
 */
static
int addresscmp (void* addr1, void* addr2) {
	return memcmp (addr1, addr2, 6);
}

/* tcpcmp
 *
 * Comparison function for two tcp server info structs
 */
static
int addresscmp (void* tcp1, void* tcp2) {
	return memcmp (tcp1, tcp2, sizeof(saved_tcp));
}

/* freepair
 *
 * Free a key value pair in the hash table
 */
static
void freepair (void* key, void* val) {
	free(key);
	free(val);
}