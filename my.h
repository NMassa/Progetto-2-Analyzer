#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <stdarg.h>
#include <pcap.h>

void liv7(u_int,const u_char *);
void liv4(u_int,u_int,const u_char *);
void liv3(u_int,const u_char *);
void liv2(u_char *,const struct pcap_pkthdr *,const u_char *);
void colore(int);
void o_colore(int);
void myprintf(const char *, ...);
void print_ipv4(const u_char *);
void print_ipv6(const u_char *);
void print_liv2(const u_char *);
void bits_from(u_char *bits,u_char byte);
void int_bits_from(u_int *bits,u_char byte);
int str2int(unsigned char str[]);
int str2int2(unsigned char str[]);
int str2int16(unsigned char str[]);
void reverse(unsigned char *bits, unsigned char *dest);
void reverse_array(u_char *pointer,int n);

struct filt_ipv4 {
	u_char sip[4]; // indirizzo sorgente
	u_char scid; // maschera sorgente
	u_char dip[4]; // indirizzo destinazione
	u_char dcid; // maschera destinazione
	struct filt_ipv4 *next;
};

struct filt_ipv6 {
	u_char sip[16]; // indirizzo sorgente
	u_char scid; // maschera sorgente
	u_char dip[16]; // indirizzo destinazione
	u_char dcid; // maschera destinazione
	struct filt_ipv6 *next;
};

struct filt_tcp {
	u_int ssap; // porta sorgente
	u_int dsap; // porta destinazione
	struct filt_tcp *next;
};

struct filt_udp {
	u_int ssap; // porta sorgente
	u_int dsap; // porta destinazione
	struct filt_udp *next;
};

struct filt_mqtt{
	u_char topic[255];
	struct filt_mqtt *next;
};


extern char outbuf[];
extern int olen;
extern int p_liv2;
extern int p_ipv4;
extern int r_ipv4;
extern struct filt_ipv4 *filt_ipv4;
extern int p_ipv6;
extern int r_ipv6;
extern struct filt_ipv6 *filt_ipv6;
extern int p_udp;
extern int r_udp;
extern struct filt_udp *filt_udp;
extern int p_tcp;
extern int r_tcp;
extern struct filt_tcp *filt_tcp;
extern int p_mqtt;
extern int r_mqtt;
extern struct filt_mqtt *filt_mqtt;
extern int p_arp;
extern int p_igmp;
extern int p_icmp;
extern int filt_kill;
extern int unknown;
extern int decoded;
extern int p_filt_kill;
extern int p_unknown;
extern int p_decoded;
extern char device[];
extern FILE *mem;
