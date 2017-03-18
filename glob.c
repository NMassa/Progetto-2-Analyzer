#include<stdio.h>

char outbuf[2000];
int olen=0;
int filt_kill;
int unknown;
int decoded;

int p_liv2=0;
int p_ipv4=0;
int r_ipv4=0;
struct filt_ipv4 *filt_ipv4=0;
int p_ipv6=0;
int r_ipv6=0;
struct filt_ipv6 *filt_ipv6=0;
int p_udp=0;
int r_udp=0;
struct filt_tcp *filt_udp=0;
int p_tcp=0;
int r_tcp=0;
struct filt_tcp *filt_tcp=0;
int p_arp=0;
int p_igmp=0;
int p_icmp=0;
int p_filt_kill=0;
int p_unknown=0;
int p_decoded=0;
char device[30];
FILE *mem;
