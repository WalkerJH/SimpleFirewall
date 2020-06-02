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
#define LOG       "logfile"
#define TEAMADDR1 "teamaddr1"
#define TEAMADDR2 "teamaddr2"
#define TEAMADDR3 "teamaddr3"
#define SRVPORT   "srvport"

/* Globals  */
static char* conffile   = STR(SYSCONFDIR) "/wfw.cfg";
static bool  printusage = false;

/* Types */
typedef struct frame {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t type;
	uint8_t payload[1500];
} frame_t;

enum frametypes {
	TYPE_IPV6 = 0xdd86,
};

typedef struct packet {
	uint32_t version: 4;
	uint32_t traffic_class: 8;
	uint32_t flow_label: 20;
	uint16_t payload_length;
	uint8_t next_header;
	uint8_t hop_limit;
	uint8_t source_addr[16];
	uint8_t destination_addr[16];
	uint8_t headers[];
} packet_t;

enum headers {
	NEXT_TCP = 0x6,
	NEXT_UDP = 0x11,
};

typedef struct tcpsegment {
	uint16_t source_port;
	uint16_t destination_port;
	uint32_t sequence_number;
	uint32_t ack_number;
	uint16_t empty0: 4;
	uint16_t header_size: 4;
	uint16_t FIN: 1;
	uint16_t SYN: 1;
	uint16_t RST: 1;
	uint16_t PSH: 1;
	uint16_t ACK: 1;
	uint16_t URG: 1;
	uint16_t empty1: 2;
	uint16_t receive_window;
	uint16_t checksum;
	uint8_t options[];
} tcpsegment_t;

typedef struct saved_tcp {
	uint16_t local_port;
	uint16_t remote_port;
	uint8_t remote_addr[16];
} saved_tcp_t;

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
 * localaddr   The IPv4 addr to bind this socket to.
 * port           The port number to bind this socket to.
 *
 * This function creates a bound socket.  Notice that both the local addr and
 * the port number are strings.  
 */
static
int ensuresocket(char* localaddr, char* port);

/* Make Socket addr
 * addr, port  The string representation of an IPv4 socket addr.
 *
 * This is a convince routine to convert an addr-port pair to an IPv4 socket
 * addr.  
 */
static
struct sockaddr_in makesockaddr(char* addr, char* port);

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
 * bcaddr  The broadcast addr for the virtual ethernet link.
 *
 * This is the main loop for wfw.  Data from the tap is broadcast on the
 * socket.  Data broadcast on the socket is written to the tap.  
 */
static
void bridge(int tap, int in, int out, struct sockaddr_in bcaddr,
            struct sockaddr_in teamaddr1, struct sockaddr_in teamaddr2,
            int srv, struct sockaddr_in srvaddr, FILE* logfile);

/* sendtraffic
 *
 * Send traffic out
 */
static
void sendtraffic(int tap, int out, struct sockaddr_in bcaddr,
                 hashtable* known_addrs, hashtable* known_tcp, hashtable* blacklist,
                 FILE* logfile);

/* gettraffic
 *
 * Recieve traffic on given device
 */
static
void gettraffic (int tap, int socket, struct sockaddr_in teamaddr1, struct sockaddr_in teamaddr2,
                 hashtable* known_addrs, hashtable* known_tcp, hashtable* blacklist,
                 FILE* logfile);

/* addrcmp
 *
 * Comparison function for two MAC addres
 */
static
int addrcmp(void* addr1, void* addr2);

/* tcpcmp
 *
 * Comparison function for two tcp server info structs
 */
static
int tcpcmp(void* tcp1, void* tcp2);

/* ipaddrcmp
 *
 * Comparison function for two ipv6 addres
 */
static
int ipaddrcmp(void* ipaddr1, void* ipaddr2);

/* freepair
 *
 * Free a key value pair in the hash table
 */
static
void freepair(void* key, void* val);

/* memdup
 *
 * Malloc and copy memory
 */
static
void* memdup(void* addr, size_t size);

/* isbcaddr
 *
 * Check for broadcast MAC addr
 */
static
int isbcaddr(uint8_t addr[6]);

/* blacklist_init
 *
 * Initialize TCP blacklist server
 */
static
void blacklist_init(hashtable conf, struct sockaddr_in* srvaddr, int* srv);

/* teaminit
 *
 * Initialize team member's servers
 */
static
void teaminit(hashtable conf, struct sockaddr_in* s1,
              struct sockaddr_in* s2, struct sockaddr_in* s3);

/* blacklist_get
 *
 * Recieve blacklisted IP(s) and send my blacklist table
 */
static
void blacklist_get(int srv, struct sockaddr_in srvaddr, hashtable* blacklist,
                   FILE* logfile);

/* blacklist_send
 *
 * Send blacklisted IP and get blacklist table
 */
static
void blacklist_send(struct sockaddr_in s, uint8_t* iptosend, hashtable* blacklist,
                    FILE* logfile);

/* readint
 *
 * reads integer from the file
 */
static
int readint(FILE* f);

/* createlog
 *
 * Create the log file
 */
static
FILE* createlog(hashtable conf);

/* logip6
 *
 * Write <label>: <ip addr> to the log file
 */
static
void logip6(FILE* logfile, char* label, uint8_t ip[16]);

/* logmac
 *
 * Write <label>: <mac addr> to the log file
 */
static
void logmac(FILE* logfile, char* label, uint8_t mac[6]);

/* daemonize
 *
 * Make this a background daemon process
 */
static
void daemonize(hashtable conf);

/* parseaddr
 *
 * parse ip addr from chunk of chars
 */
static
uint8_t* parseaddr(char* addrstr, size_t size);

/* parseaddr_s
 *
 * parse ip addr from readable string
 */
static
uint8_t* parseaddr_s(char* addrstr, size_t size);

/* writeaddr
 *
 * write ip addr to file
 */
static
void writeaddr(FILE* f, uint8_t ip[16]);


/* Main
 * 
 * Parse the command line & the conf file.
 * Initialize, then call bridge, then clean up.
 */
int main(int argc, char* argv[]) {
	puts("WFW Initialized\n");
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

    int srv;
    struct sockaddr_in srvaddr;
	  blacklist_init(conf, &srvaddr, &srv);

	  struct sockaddr_in teamaddr1;
	  struct sockaddr_in teamaddr2;
	  struct sockaddr_in teamaddr3;
	  teaminit(conf, &teamaddr1, &teamaddr2, &teamaddr3);

    daemonize(conf);

    FILE *logfile = createlog(conf);

    bridge(tap, in, out, bcaddr, teamaddr1, teamaddr2, srv, srvaddr, logfile);
    
    close(in);
    close(out);
    close(tap);
    htfree(conf);

    fclose(logfile);
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
  if(fd == -1) {
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
  if(sock == -1) {
    perror("socket");
    exit (EXIT_FAILURE);
  }

  int bcast = 1;
  if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
                       &bcast, sizeof(bcast)) == -1) {
    perror("setsockopt(broadcast)");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_in addr = makesockaddr(localaddr, port);
  if(bind(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
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
void bridge(int tap, int in, int out, struct sockaddr_in bcaddr,
						struct sockaddr_in teamaddr1, struct sockaddr_in teamaddr2,
						int srv, struct sockaddr_in srvaddr, FILE* logfile) {
#define BUFSZ 1514

	fd_set rdset;

	int maxfd = mkfdset(&rdset, tap, in, out, srv, 0);

	hashtable known_addrs = htnew(32, addrcmp, freepair);
	hashtable known_tcp   = htnew(32, tcpcmp, freepair);
	hashtable blacklist   = htnew(32, ipaddrcmp, freepair);

	while (0 <= select(1 + maxfd, &rdset, NULL, NULL, NULL)) {

		if (FD_ISSET(tap, &rdset)) {
			sendtraffic(tap, out, bcaddr, &known_addrs, 
				&known_tcp, &blacklist, logfile);
		}

		else if (FD_ISSET(in, &rdset)) {
			gettraffic(tap, in, teamaddr1, teamaddr2,
				&known_addrs, &known_tcp, &blacklist, logfile);
		}

		else if (FD_ISSET(out, &rdset)) {
			gettraffic(tap, out, teamaddr1, teamaddr2,
				&known_addrs, &known_tcp, &blacklist, logfile);
		}

		else if (FD_ISSET(srv, &rdset)) {
			blacklist_get(srv, srvaddr, &blacklist, logfile);
		}

		maxfd = mkfdset(&rdset, tap, in, out, srv, 0);
	}

	htfree(known_addrs);
	htfree(known_tcp);
	htfree(blacklist);
}

/* sendtraffic
 *
 * Send traffic out
 */
static
void sendtraffic(int tap, int out, struct sockaddr_in bcaddr,
									hashtable* known_addrs, hashtable* known_tcp, 
									hashtable* blacklist, FILE* logfile) {
	frame_t *frame  = malloc(sizeof(frame_t));
	ssize_t rdct = read(tap, (void*)frame, BUFSZ);
	if (rdct < 0) {
		perror("read");
	} else {
		struct sockaddr_in* socket;
		socket = &bcaddr;

		if (hthaskey(*known_addrs, frame->dst, 6)) {
			socket = (struct sockaddr_in *)htfind(*known_addrs, frame->dst, 6);
		}
		if (sendto(out, (void *)frame, rdct, 0,
		           (struct sockaddr *)socket, sizeof(struct sockaddr_in)) == -1) {
			perror("sendto");
		}

		if (frame->type == TYPE_IPV6) {
			packet_t *packet = (packet_t *)frame->payload;
			if (packet->next_header == NEXT_TCP) {
				tcpsegment_t *segment = (tcpsegment_t *)packet->headers;
				if (segment->SYN) {
					saved_tcp_t *new_tcp = malloc(sizeof(saved_tcp_t));
					memcpy(&new_tcp->local_port, &segment->source_port, 2);
					memcpy(&new_tcp->remote_port, &segment->destination_port, 2);
					memcpy(&new_tcp->remote_addr, &packet->destination_addr, 16);

					if (!hthaskey(*known_tcp, new_tcp, sizeof(saved_tcp_t))) {
						htinsert(*known_tcp, new_tcp, sizeof(saved_tcp_t), 0);
						logip6(logfile, "Initiated TCP to", packet->destination_addr);
					}
				}
			}
		}
	}
	free(frame);
}

/* gettraffic
 *
 * Recieve traffic on given device
 */
static
void gettraffic (int tap, int socket, struct sockaddr_in teamaddr1, 
									struct sockaddr_in teamaddr2,
									hashtable* known_addrs, hashtable* known_tcp, hashtable* blacklist,
									FILE* logfile) {
	int valid = 1;
	struct sockaddr_in from;
	frame_t *frame = malloc(sizeof(frame_t));
	socklen_t flen = sizeof(from);
	ssize_t rdct = recvfrom(socket, (void*)frame, BUFSZ, 0,
		(struct sockaddr *) &from, &flen);
	if (rdct < 0) {
		perror("recvfrom");
	} else {

		if (frame->type == TYPE_IPV6) {
			packet_t *packet = (packet_t *) frame->payload;
			if (hthaskey(*blacklist, packet->source_addr, 16)) {
				valid = 0;
			}
			if (packet->next_header == NEXT_TCP) {
				tcpsegment_t *segment = (tcpsegment_t *) packet->headers;
				if (segment->SYN) {
					saved_tcp_t *new_tcp = malloc(sizeof(saved_tcp_t));
					memcpy(&new_tcp->local_port, &segment->destination_port, 2);
					memcpy(&new_tcp->remote_port, &segment->source_port, 2);
					memcpy(&new_tcp->remote_addr, &packet->source_addr, 16);

					if (!hthaskey(*known_tcp, new_tcp, sizeof(saved_tcp_t))) {
						valid = 0;
						if (!hthaskey(*blacklist, packet->source_addr, 16)) {
							void *key = memdup(packet->source_addr, 16);
							htinsert(*blacklist, key, 16, 0);

							void *iptosend = memdup(packet->source_addr, 16);
							blacklist_send(teamaddr1, iptosend, blacklist, logfile);
							blacklist_send(teamaddr2, iptosend, blacklist, logfile);

							logip6(logfile, "Bad IP", packet->source_addr);
						}
					}
					free(new_tcp);
				}
			}
		}

		if (valid) {
			if (write(tap, (void *) frame, rdct) == -1) {
				perror("write");
			}
			if (!isbcaddr(frame->src)) {
				if (!hthaskey(*known_addrs, frame->src, 6)) {
					void *key = memdup(frame->src, 6);
					void *val = memdup(&from, sizeof(struct sockaddr_in));
					htinsert(*known_addrs, key, 6, val);
					logmac(logfile, "Added MAC", frame->src);
				} else {
					memcpy(htfind(*known_addrs, frame->src, 6),
					       &from, sizeof(struct sockaddr_in));
				}
			}
		}
	}
	free(frame);
}

/* addrcmp
 *
 * Comparison function for two MAC addres
 */
static
int addrcmp (void* addr1, void* addr2) {
	return memcmp (addr1, addr2, 6);
}

/* tcpcmp
 *
 * Comparison function for two tcp server info structs
 */
static
int tcpcmp (void* tcp1, void* tcp2) {
	return memcmp (tcp1, tcp2, sizeof(saved_tcp_t));
}

/* ipaddrcmp
 *
 * Comparison function for two ipv6 addres
 */
static
int ipaddrcmp(void* ipaddr1, void* ipaddr2) {
	return memcmp (ipaddr1, ipaddr2, 16);
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

/* memdup
 *
 * Malloc and copy memory
 */
static
void* memdup(void* mem, size_t size) {
	void* newmem = malloc(size);
	memcpy(newmem, mem, size);
	return newmem;
}

/* isbcaddr
 *
 * Check for broadcast MAC addr
 */
static
int isbcaddr(uint8_t addr[6]) {
	uint8_t bc[6] = {0};
	for (int i = 0; i < 6; i++) {
		bc[i] = 0xFF;
	}
	uint8_t mc[6] = {0};
	mc[0] = 0x33;
	mc[1] = 0x33;
	int r = false;
	if (memcmp(&bc, &addr, 6) == 0 || memcmp(&mc, &addr, 2) == 0)
		r = true;
	return r;
}

/* blacklist_init
 *
 * Initialize TCP blacklist server
 */
static
void blacklist_init(hashtable conf, struct sockaddr_in* srvaddr, int* srv) {
	int port = atoi(htstrfind(conf, SRVPORT));
	printf("Initializing TCP server on port %d\n", port);
	fflush(stdout);

	int s = socket(AF_INET, SOCK_STREAM, 0);

	struct sockaddr_in addr;
	bzero(&addr, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = 0;

	if (bind(s, (struct sockaddr*)&addr, sizeof(addr)) == -1) {
		perror("bind");
		close(s);
		exit(EXIT_FAILURE);
	}
	if (listen(s, 1) == -1) {
		perror("listen");
		close(s);
		exit(EXIT_FAILURE);
	}

	memcpy(srvaddr, &addr, sizeof(addr));
	memcpy(srv, &s, sizeof(int));
	printf("TCP Server running on port %d\n", htons(srvaddr->sin_port));
	fflush(stdout);
}

/* teaminit
 *
 * Initialize team member's servers
 */
static
void teaminit(hashtable conf, struct sockaddr_in* s1,
              struct sockaddr_in* s2, struct sockaddr_in* s3) {
	if (hthasstrkey(conf, TEAMADDR1)) {
		struct sockaddr_in _s1 = makesockaddr(htstrfind(conf, TEAMADDR1),
		                                      htstrfind(conf, SRVPORT));
		memcpy(s1, &_s1, sizeof(struct sockaddr_in));
	}
	if (hthasstrkey(conf, TEAMADDR2)) {
		struct sockaddr_in _s2 = makesockaddr(htstrfind(conf, TEAMADDR2),
		                                      htstrfind(conf, SRVPORT));
		memcpy(s2, &_s2, sizeof(struct sockaddr_in));
	}
	if (hthasstrkey(conf, TEAMADDR3)) {
		struct sockaddr_in _s3 = makesockaddr(htstrfind(conf, TEAMADDR3),
		                                      htstrfind(conf, SRVPORT));
		memcpy(s3, &_s3, sizeof(struct sockaddr_in));
	}
}

/* blacklist_get
 *
 * Recieve blacklisted IP(s) and send my blacklist table
 */
static
void blacklist_get(int srv, struct sockaddr_in srvaddr, hashtable* blacklist,
										FILE* logfile) {
	socklen_t len = sizeof(srvaddr);
	int c = accept(srv, (struct sockaddr *)&srvaddr, &len);
	FILE *srvfile = fdopen(c, "w+");

	int num = readint(srvfile);
	fprintf(logfile, "getting %d ips from network\n", num);
	fflush(logfile);

	for (int i = 0; i < num; i++) {
		char addrstr[33];
		fgets(addrstr, 33, srvfile);
		uint8_t* addr = parseaddr(addrstr, 16);
		htinsert(*blacklist, addr, 16, 0);
		logip6(logfile, "Bad IP from network", addr);
	}

	fprintf(srvfile, "%d\n", htgetload(*blacklist));
	fflush(srvfile);
	for (int i = 0; i < 32; i++) {
		uint8_t* ip = (uint8_t*)htgetkey(*blacklist, i);
		if (ip != NULL) {
			writeaddr(srvfile, ip);
		}
	}
	close(c);
}

/* blacklist_send
 *
 * Send blacklisted IP and get blacklist table
 */
static
void blacklist_send(struct sockaddr_in groupaddr, 
										uint8_t* iptosend, hashtable* blacklist,FILE* logfile) {
	int s = socket(PF_INET, SOCK_STREAM, 0);
	if (connect(s, (struct sockaddr *)&groupaddr, sizeof(groupaddr)) != -1) {
		fprintf(logfile, "Connected to group member's server successfully\n");
		fflush(logfile);

		FILE *srvfile = fdopen(s, "w+");

		fprintf(srvfile, "1\n");
		fflush(srvfile);
		writeaddr(srvfile, iptosend);

		int num = readint(srvfile);

		if (num > 0) {
			for (int i = 0; i < num; i++) {
				char addrstr[33];
				fgets(addrstr, 33, srvfile);
				uint8_t* addr = parseaddr(addrstr, 16);
				htinsert(*blacklist, addr, 16, 0);
				logip6(logfile, "Bad IP from network", addr);
			}
		}
		close(s);
	} else {
		perror("connect");
		fprintf(logfile, "Failed to connect\n");
		fflush(logfile);
		close(s);
	}
}

/* readint
 *
 * reads integer from the file
 */
static
int readint(FILE* f) {
	int num = 0;
	char numstr[6];
	fgets(numstr, 6, f);
	num = atoi(numstr);
	return num;
}
/* createlog
 *
 * Create the log file
 */
static
FILE* createlog(hashtable conf) {
	FILE *f;
	if (hthasstrkey(conf, LOG)) {
		f = fopen(htstrfind(conf, LOG), "w");
		fprintf(f, "--Firewall Log--\n");
		fflush(f);
	}
	return f;
}

/* logip6
 *
 * Write <label>: <ip addr> to the log file
 */
static
void logip6(FILE* logfile, char* label, uint8_t ip[16]) {
	fprintf(logfile, "%-20s", label);
	for (int i = 0; i < 16; i++) {
		if (i%2 == 0 && i != 0)
			fprintf(logfile, ":");
		fprintf(logfile, "%x", ip[i]);
	}
	fprintf(logfile, "\n");
	fflush(logfile);
}

/* logmac
 *
 * Write <label>: <mac addr> to the log file
 */
static
void logmac(FILE* logfile, char* label, uint8_t mac[6]) {
	fprintf(logfile, "%-20s", label);
	for (int i = 0; i < 6; i++) {
		if (i%2 == 0 && i != 0)
			fprintf(logfile, "-");
		fprintf(logfile, "%X", mac[i]);
	}
	fprintf(logfile, "\n");
	fflush(logfile);
}

/* daemonize
 *
 * Make this a background daemon process
 */
static
void daemonize(hashtable conf) {
	daemon(0,0);
	if (hthasstrkey(conf, PID)) {
		FILE *pidfile = fopen(htstrfind(conf, PID), "w");
		if (pidfile != NULL) {
			fprintf(pidfile, "%d\n", getpid());
			fclose(pidfile);
		}
	}
}

/* parseaddr
 *
 * parse ip addr from chars
 */
static
uint8_t* parseaddr(char* addrstr, size_t size) {
	uint8_t* addr = malloc(sizeof(uint8_t)*size);
	for (int i = 0; i < size; i ++) {
		addr[i] = addrstr[i];
	}
	return addr;
}

/* parseaddr_s
 *
 * parse ip addr from readable string
 */
static
uint8_t* parseaddr_s(char* addrstr, size_t size) {
	uint8_t* addr = malloc(sizeof(uint8_t)*size);
	for (int i = 0; i < size; i ++) {
		char s[2];
		sprintf(s, "%c%c", addrstr[i*2], addrstr[i*2+1]);
		addr[i] = strtol(s, NULL, 16);
	}
	return addr;
}

/* writeaddr
 *
 * write ip addr to file
 */
static
void writeaddr(FILE* f, uint8_t ip[16]) {
	for (int i = 0; i < 16; i++) {
		fprintf(f, "%c", ip[i]);
	}
	fprintf(f, "\n");
	fflush(f);
}