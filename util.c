#include "my.h"

char fg[]={0,1,2,3,4,5,6};
char bg[]={8,8,8,8,8,8,8};

void colore(int col){
	col%=sizeof(fg);
	myprintf("\033[0;%d;%dm",30+fg[col],40+bg[col]);
}

void o_colore(int col){
	col%=sizeof(fg);
	printf("\033[0;%d;%dm",30+fg[col],40+bg[col]);
}


void myprintf(const char *fmt, ...){
	va_list ap;
	va_start(ap,fmt);
	vsprintf(outbuf+olen,fmt,ap);
	va_end(ap);
	olen+=strlen(outbuf+olen);
}

void print_liv2(const u_char *p){
	int i;
	for(i=0;;i++){
		myprintf("%x",*p++);
		if(i==5)break;
		myprintf(":");
	}
}

void print_ipv4(const u_char *p){
	const u_char *mp;
	int i;
	for(mp=p,i=0;;i++){
		myprintf("%d",*mp++);
		if(i==3)break;
		myprintf(".");
	}
}

void print_ipv6(const u_char *p){
	const u_char *mp;
	int i;
	for(mp=p,i=0;;i++){
		myprintf("%x",ntohs(*(u_int *)mp));
		if(i==7)break;
		mp+=2;
		myprintf(":");
	}
}

void bits_from(unsigned char *bits, u_char byte)
{
	for (int i = 0; i < 8; i++) {
		// Mask each bit in the byte and store it
		bits[i] = (byte & (1 << i)) != 0;
	}
}

int str2int(u_char s[]){
	int numero =0;
	for (int i =0; i<8; i++)
	{
		if(s[i] == '\001')
		{
			numero |= 1 << (7-i);
		}
	}
	return numero;
}

void reverse(unsigned char *bits, unsigned char *dest)
{
	int c = sizeof(bits) - 1;
	for(int i=0;i < sizeof(bits);i++)
	{
		dest[c] = bits[i];
		c--;
	}
}