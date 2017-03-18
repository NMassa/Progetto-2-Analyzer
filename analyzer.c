#include "my.h"

#define LENSNIF 1500

void main(int argc,char **argv){
  char buffer[200],*aux;
  pcap_t *pd;
  struct bpf_program fcode;
  struct filt_ipv4 *aux_ipv4,*aux1_ipv4;
  struct filt_ipv6 *aux_ipv6,*aux1_ipv6;
  struct filt_tcp *aux_tcp,*aux1_tcp;
  struct filt_udp *aux_udp,*aux1_udp;
  int i;
  u_int aux_ui;
  FILE *fp;

  if(argc!=2){
    fprintf(stderr,"Use %s config_file\n",argv[0]);
    exit(1);
  }

    char fullpath[256];
    snprintf(fullpath, sizeof fullpath, "%s%s", "/home/massa/Scrivania/SPLI/Progetto 2 - Analyzer/", argv[1]);
  fp=fopen(fullpath,"rt");
  if(fp==NULL)exit(1);
  for(;;){
    fscanf(fp,"%s",buffer);
    if(strcmp(buffer,"end")==0)break;
    if(strcmp(buffer,"device")==0){
      fscanf(fp,"%s",device);
    }
    if(strcmp(buffer,"print")==0){
      for(;;){
	fscanf(fp,"%s",buffer);
	if(strcmp(buffer,"filt_kill")==0)p_filt_kill=1;
	if(strcmp(buffer,"unknown")==0)p_unknown=1;
	if(strcmp(buffer,"decoded")==0)p_decoded=1;
	if(strcmp(buffer,"end_print")==0)break;
      }
    }
    if(strcmp(buffer,"ether")==0){
      for(;;){
	fscanf(fp,"%s",buffer);
	if(strcmp(buffer,"print")==0)p_liv2=1;
	if(strcmp(buffer,"end_ether")==0)break;
      }
    }
    if(strcmp(buffer,"arp")==0){
      for(;;){
	fscanf(fp,"%s",buffer);
	if(strcmp(buffer,"print")==0)p_arp=1;
	if(strcmp(buffer,"end_arp")==0)break;
      }
    }
    if(strcmp(buffer,"igmp")==0){
      for(;;){
	fscanf(fp,"%s",buffer);
	if(strcmp(buffer,"print")==0)p_igmp=1;
	if(strcmp(buffer,"end_igmp")==0)break;
      }
    } 
    if(strcmp(buffer,"icmp")==0){
      for(;;){
	fscanf(fp,"%s",buffer);
	if(strcmp(buffer,"print")==0)p_icmp=1;
	if(strcmp(buffer,"end_icmp")==0)break;
      }
    }
    if(strcmp(buffer,"ipv4")==0){
      for(;;){
	fscanf(fp,"%s",buffer);
	if(strcmp(buffer,"print")==0)p_ipv4=1;
	if(strcmp(buffer,"run")==0)r_ipv4=1;
	if(strcmp(buffer,"filt")==0){
	  aux1_ipv4=filt_ipv4;
	  if(aux1_ipv4!=NULL)
	    while(aux1_ipv4->next!=NULL)aux1_ipv4=aux1_ipv4->next;
	  aux_ipv4=(struct filt_ipv4 *)malloc(sizeof(struct filt_ipv4));
	  if(aux_ipv4==NULL)exit(1);
	  if(aux1_ipv4==NULL)filt_ipv4=aux_ipv4;
	  else aux1_ipv4->next=aux_ipv4;
	  fscanf(fp,"%s",buffer);
	  aux=strtok(buffer,".");
	  aux_ipv4->sip[0]=atoi(aux);
	  for(i=1;i<4;i++){
	    aux=strtok(NULL,".");
	    aux_ipv4->sip[i]=atoi(aux);
	  }
	  fscanf(fp,"%s",buffer);
	  aux_ipv4->scid=atoi(buffer);
	  fscanf(fp,"%s",buffer);
	  aux=strtok(buffer,".");
	  aux_ipv4->dip[0]=atoi(aux);
	  for(i=1;i<4;i++){
	    aux=strtok(NULL,".");
	    aux_ipv4->dip[i]=atoi(aux);
	  }
	  fscanf(fp,"%s",buffer);
	  aux_ipv4->dcid=atoi(buffer);
	  aux_ipv4->next=NULL;
	}
	if(strcmp(buffer,"end_ipv4")==0)break;
      }
    }
    if(strcmp(buffer,"ipv6")==0){
      for(;;){
	fscanf(fp,"%s",buffer);
	if(strcmp(buffer,"print")==0)p_ipv6=1;
	if(strcmp(buffer,"run")==0)r_ipv6=1;
	if(strcmp(buffer,"filt")==0){
	  aux1_ipv6=filt_ipv6;
	  if(aux1_ipv6!=NULL)
	    while(aux1_ipv6->next!=NULL)aux1_ipv6=aux1_ipv6->next;
	  aux_ipv6=(struct filt_ipv6 *)malloc(sizeof(struct filt_ipv6));
	  if(aux_ipv6==NULL)exit(1);
	  if(aux1_ipv6==NULL)filt_ipv6=aux_ipv6;
	  else aux1_ipv6->next=aux_ipv6;
	  fscanf(fp,"%s",buffer);
	  aux=strtok(buffer,":");
	  aux_ui=strtol(aux,(char **)NULL,16);
	  aux_ipv6->sip[0]=aux_ui/256;
	  aux_ipv6->sip[1]=aux_ui%256;
	  for(i=1;i<8;i++){
	    aux=strtok(NULL,":");
	    aux_ui=strtol(aux,(char **)NULL,16);
	    aux_ipv6->sip[2*i]=aux_ui/256;
	    aux_ipv6->sip[2*i+1]=aux_ui%256;
	  }
	  fscanf(fp,"%s",buffer);
	  aux_ipv6->scid=atoi(buffer);
	  fscanf(fp,"%s",buffer);
	  aux=strtok(buffer,":");
	  aux_ui=strtol(aux,(char **)NULL,16);
	  aux_ipv6->dip[0]=aux_ui/256;
	  aux_ipv6->dip[1]=aux_ui%256;
	  for(i=1;i<8;i++){
	    aux=strtok(NULL,":");
	    aux_ui=strtol(aux,(char **)NULL,16);
	    aux_ipv6->dip[2*i]=aux_ui/256;
	    aux_ipv6->dip[2*i+1]=aux_ui%256;
	  }
	  fscanf(fp,"%s",buffer);
	  aux_ipv6->dcid=atoi(buffer);
	  aux_ipv6->next=NULL;
	}
	if(strcmp(buffer,"end_ipv6")==0)break;
      }
    }
    if(strcmp(buffer,"tcp")==0){
      for(;;){
	fscanf(fp,"%s",buffer);
	if(strcmp(buffer,"print")==0)p_tcp=1;
	if(strcmp(buffer,"run")==0)r_tcp=1;
	if(strcmp(buffer,"filt")==0){
	  aux1_tcp=filt_tcp;
	  if(aux1_tcp!=NULL)
	    while(aux1_tcp->next!=NULL)aux1_tcp=aux1_tcp->next;
	  aux_tcp=(struct filt_tcp *)malloc(sizeof(struct filt_tcp));
	  if(aux_tcp==NULL)exit(1);
	  if(aux1_tcp==NULL)filt_tcp=aux_tcp;
	  else aux1_tcp->next=aux_tcp;
	  fscanf(fp,"%s",buffer);
	  aux_tcp->ssap=atoi(buffer);
	  fscanf(fp,"%s",buffer);
	  aux_tcp->dsap=atoi(buffer);
	  aux_tcp->next=NULL;
	}
	if(strcmp(buffer,"end_tcp")==0)break;
      }
    }
    if(strcmp(buffer,"udp")==0){
      for(;;){
	fscanf(fp,"%s",buffer);
	if(strcmp(buffer,"print")==0)p_udp=1;
	if(strcmp(buffer,"run")==0)r_udp=1;
	if(strcmp(buffer,"filt")==0){
	  aux1_udp=filt_udp;
	  if(aux1_udp!=NULL)
	    while(aux1_udp->next!=NULL)aux1_udp=aux1_udp->next;
	  aux_udp=(struct filt_udp *)malloc(sizeof(struct filt_udp));
	  if(aux_udp==NULL)exit(1);
	  if(aux1_udp==NULL)filt_udp=aux_udp;
	  else aux1_udp->next=aux_udp;
	  fscanf(fp,"%s",buffer);
	  aux_udp->ssap=atoi(buffer);
	  fscanf(fp,"%s",buffer);
	  aux_udp->dsap=atoi(buffer);
	  aux_udp->next=NULL;
	}
	if(strcmp(buffer,"end_udp")==0)break;
      }
    }
  }
 
  mem=fopen("log","wt");
  pd=pcap_open_live(device,LENSNIF,0,1000,buffer);
  if(pd==NULL)exit(1);
  pcap_loop(pd,-1,liv2,buffer);
  //pcap_loop(pd,-1,liv2,dati);	
}
