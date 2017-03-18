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


struct filt_ipv4 {
  u_char sip[4];
  u_char scid;
  u_char dip[4];
  u_char dcid;
  struct filt_ipv4 *next;
};

struct filt_ipv6 {
  u_char sip[16];
  u_char scid;
  u_char dip[16];
  u_char dcid;
  struct filt_ipv6 *next;
};

struct filt_tcp {
  u_int ssap;
  u_int dsap;
  struct filt_tcp *next;
};

struct filt_udp {
  u_int ssap;
  u_int dsap;
  struct filt_udp *next;
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
