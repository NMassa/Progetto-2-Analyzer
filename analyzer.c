#include "my.h"
#include "path.h"

#define LENSNIF 1500

void main(int argc,char **argv){
    char buffer[200],*aux;
    pcap_t *pd;
    struct bpf_program fcode;
    struct filt_ipv4 *aux_ipv4,*aux1_ipv4;
    struct filt_ipv6 *aux_ipv6,*aux1_ipv6;
    struct filt_tcp *aux_tcp,*aux1_tcp;
    struct filt_udp *aux_udp,*aux1_udp;
    struct filt_mqtt *aux_mqtt,*aux1_mqtt;
    int i;
    u_int aux_ui;
    FILE *fp;

    // Controllo argomenti
    if(argc!=2){
        fprintf(stderr,"Use %s config_file\n",argv[0]);
        exit(1);
    }

    // Lettura file config
    char fullpath[256];
    snprintf(fullpath, sizeof fullpath, "%s%s", PATH, argv[1]);
    fp=fopen(fullpath,"rt");
    if(fp==NULL){
        printf("File config NULL");
        exit(1);
    }

    // Parsing file config
    for(;;){
        fscanf(fp,"%s",buffer);
        if(strcmp(buffer,"end")==0)break; // fine del file config
        if(strcmp(buffer,"device")==0){ // Interfaccia di rete
            fscanf(fp,"%s",device);
        }
        if(strcmp(buffer,"print")==0){
            for(;;){
                fscanf(fp,"%s",buffer);
                if(strcmp(buffer,"filt_kill")==0)p_filt_kill=1; // Flag disattiva tutti i filtri
                if(strcmp(buffer,"unknown")==0)p_unknown=1; // Flag stampa i pacchetti non riconosciuti
                if(strcmp(buffer,"decoded")==0)p_decoded=1; // Flag stampa i pacchetti decodificati
                if(strcmp(buffer,"end_print")==0)break;
            }
        }
        if(strcmp(buffer,"ether")==0){  // Protocollo Ethernet
            for(;;){
                fscanf(fp,"%s",buffer);
                if(strcmp(buffer,"print")==0)p_liv2=1; // Flag stampa livello 2 (non c'è il run perchè se non si analizza il livello 2 non funziona più niente)
                if(strcmp(buffer,"end_ether")==0)break;
            }
        }
        if(strcmp(buffer,"arp")==0){ // Protocollo ARP
            for(;;){
                fscanf(fp,"%s",buffer);
                if(strcmp(buffer,"print")==0)p_arp=1;
                if(strcmp(buffer,"end_arp")==0)break;
            }
        }
        if(strcmp(buffer,"igmp")==0){ // Protocollo IGMP
            for(;;){
                fscanf(fp,"%s",buffer);
                if(strcmp(buffer,"print")==0)p_igmp=1;
                if(strcmp(buffer,"end_igmp")==0)break;
            }
        }
        if(strcmp(buffer,"icmp")==0){ // Protocollo ICMP
            for(;;){
                fscanf(fp,"%s",buffer);
                if(strcmp(buffer,"print")==0)p_icmp=1;
                if(strcmp(buffer,"end_icmp")==0)break;
            }
        }
        if(strcmp(buffer,"ipv4")==0){ // Protocollo IPv4
            for(;;){
                fscanf(fp,"%s",buffer);
                if(strcmp(buffer,"print")==0)p_ipv4=1; // Flag di stampa
                if(strcmp(buffer,"run")==0)r_ipv4=1; // Flag di analisi

                if(strcmp(buffer,"filt")==0){ // Filtri sugli IP
                    aux1_ipv4=filt_ipv4;
                    if(aux1_ipv4!=NULL)
                        while(aux1_ipv4->next!=NULL)aux1_ipv4=aux1_ipv4->next;
                    aux_ipv4=(struct filt_ipv4 *)malloc(sizeof(struct filt_ipv4));
                    if(aux_ipv4==NULL)exit(1);
                    if(aux1_ipv4==NULL)filt_ipv4=aux_ipv4;
                    else aux1_ipv4->next=aux_ipv4;
                    fscanf(fp,"%s",buffer); // Legge un ip intero (sorgente)
                    aux=strtok(buffer,"."); // strtok (string tokenizer) divide la stringa con separatore .
                    aux_ipv4->sip[0]=atoi(aux); // Legge i vari pezzi e li assegna a ssip (ip sorgente), atoi (cast stringa in intero)
                    for(i=1;i<4;i++){
                        aux=strtok(NULL,".");
                        aux_ipv4->sip[i]=atoi(aux);
                    }
                    fscanf(fp,"%s",buffer); // Legge maschera
                    aux_ipv4->scid=atoi(buffer); //Converte ed assegna maschera

                    fscanf(fp,"%s",buffer); // Destinazione uguale a sopra
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
        if(strcmp(buffer,"ipv6")==0){ // Protocollo IPv6
            for(;;){
                fscanf(fp,"%s",buffer);
                if(strcmp(buffer,"print")==0)p_ipv6=1;
                if(strcmp(buffer,"run")==0)r_ipv6=1;

                if(strcmp(buffer,"filt")==0){ // Filtri sugli IP
                    aux1_ipv6=filt_ipv6;
                    if(aux1_ipv6!=NULL)
                        while(aux1_ipv6->next!=NULL)aux1_ipv6=aux1_ipv6->next;
                    aux_ipv6=(struct filt_ipv6 *)malloc(sizeof(struct filt_ipv6));
                    if(aux_ipv6==NULL)exit(1);
                    if(aux1_ipv6==NULL)filt_ipv6=aux_ipv6;
                    else aux1_ipv6->next=aux_ipv6;
                    fscanf(fp,"%s",buffer); //Legge ipv6, uguale a ipv4 con la differenza che bisogna interpretare la stringa esadecimale
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
        if(strcmp(buffer,"tcp")==0){ // Protocollo TCP
            for(;;){
                fscanf(fp,"%s",buffer);
                if(strcmp(buffer,"print")==0)p_tcp=1;
                if(strcmp(buffer,"run")==0)r_tcp=1;

                if(strcmp(buffer,"filt")==0){ // Filtri sulle porte sorgente e destinazione
                    aux1_tcp=filt_tcp;
                    if(aux1_tcp!=NULL)
                        while(aux1_tcp->next!=NULL)aux1_tcp=aux1_tcp->next;
                    aux_tcp=(struct filt_tcp *)malloc(sizeof(struct filt_tcp));
                    if(aux_tcp==NULL)exit(1);
                    if(aux1_tcp==NULL)filt_tcp=aux_tcp;
                    else aux1_tcp->next=aux_tcp;
                    fscanf(fp,"%s",buffer); // Legge ed assegna porta sorgente
                    aux_tcp->ssap=atoi(buffer);
                    fscanf(fp,"%s",buffer); // Legge ed assegna porta destinazione
                    aux_tcp->dsap=atoi(buffer);
                    aux_tcp->next=NULL;
                }
                if(strcmp(buffer,"end_tcp")==0)break;
            }
        }
        if(strcmp(buffer,"udp")==0){ // Protocollo UDP
            for(;;){
                fscanf(fp,"%s",buffer);
                if(strcmp(buffer,"print")==0)p_udp=1;
                if(strcmp(buffer,"run")==0)r_udp=1;

                if(strcmp(buffer,"filt")==0){ // Filtri sulle porte sorgente e destinazione, uguale a tcp
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

        // PROTOCOLLO MQTT
        if(strcmp(buffer,"mqtt")==0){
            for(;;){
                fscanf(fp,"%s",buffer);
                if(strcmp(buffer,"print")==0)p_mqtt=1;
                if(strcmp(buffer,"run")==0)r_mqtt=1;

                if(strcmp(buffer,"filt")==0){ //Filtri sui topic
                    aux1_mqtt=filt_mqtt; // variabile temporanea
                    if(aux1_mqtt!=NULL)
                        while(aux1_mqtt->next!=NULL)aux1_mqtt=aux1_mqtt->next; //se non è il primo filtro si sposta al next
                    aux_mqtt=(struct filt_mqtt *)malloc(sizeof(struct filt_mqtt)); // allocamento spazio necessario
                    if(aux_mqtt==NULL)exit(1); //c'è stato un disguido
                    if(aux1_mqtt==NULL)filt_mqtt=aux_mqtt; //se sono finiti i filtri finalizza assegnando a filt_mqtt
                    else aux1_mqtt->next=aux_mqtt; //altrimenti si aggiunge un altro filtro
                    /*
                    if(aux_mqtt == '#' || aux_mqtt == '*') //se aux_mqtt è un multilevel wildcard
                       {while(aux_mqtt!=NULL)//finchè troviamo un topic andiamo a cercarne ed aggiungerne
                           {aux1_mqtt->next=aux_mqtt;}
                       //filt_mqtt=aux_mqtt; //se sono finiti i filtri finalizza assegnando a filt_mqtt
                       }
                    filt_mqtt=aux_mqtt; //se sono finiti i filtri finalizza assegnando a filt_mqtt
                    */
                    // TODO: in questo modo legge il filtro come un'unica parola, in realtà i topic sono organizzati a livelli separati da /
                    // TODO: se c'è tempo bisognerebbe implementare il filtro multilivello come nel link sotto
                    // Vedere http://www.hivemq.com/blog/mqtt-essentials-part-5-mqtt-topics-best-practices
                    fscanf(fp,"%s",buffer); // Legge ed assegna un topic
                    strcpy(aux_mqtt->topic,buffer);
                    /*for(int n=0; n<strlen(buffer);n++)
                    {
                        while(buffer[n]!='/' && buffer[n]!='')
                        {
                        }
                        strcpy(aux_mqtt->topic,buffer);
                    }*/
                    aux_mqtt->next=NULL;
                }

                if(strcmp(buffer,"end_mqtt")==0)break;
            }
        }
    }

    mem=fopen("log","wt");

    // Inizio analisi dal livello 2
    pd=pcap_open_live(device,LENSNIF,0,1000,buffer);
    if(pd==NULL)exit(1);
    pcap_loop(pd,-1,liv2,buffer);
    //pcap_loop(pd,-1,liv2,dati);
}
