#include "my.h"

void liv2(u_char *user,const struct pcap_pkthdr *h,const u_char *p){
  int i;
  const u_char *mp;
  u_int len,type;
  char tratt[]="####################";
  
  unknown=0;
  filt_kill=0;
  decoded=0;
  olen=0;
  type=ntohs(*(u_int *)(p+12));
  len=h->len;
  if(p_liv2){
    colore(2);
    myprintf("802.3|");
    print_liv2(p+6);
    myprintf(" -> ");
    print_liv2(p);
    myprintf(" Type:%04x Len:%d",type,len);
    myprintf("\n");
  }
  liv3(type,p+14);
  if(olen!=0){
    o_colore(1);
    if(p_decoded&&decoded)printf("%s Decoded %s\n%s",tratt,tratt,outbuf);
    if(p_filt_kill&&filt_kill)printf("%s Filt_Kill %s\n%s",tratt,tratt,outbuf);
    if(p_unknown&&unknown)printf("%s Unknown %s\n%s",tratt,tratt,outbuf);
    fflush(stdout);
  }
}
