#include "my.h"
#include <string.h>
#include <ctype.h>



void liv7(u_int len, const u_char *p) {
    int i;

    if ((int) len <= 0)return;
    colore(5);

	// Lettura Fixed Header
	u_char fixed_header = *(p);
	unsigned char fixed_header_bits[8];
	bits_from(fixed_header_bits,fixed_header);

	char retain = fixed_header_bits[0];
	char QoS1 = fixed_header_bits[1];
	char QoS2 = fixed_header_bits[2];
	char dup = fixed_header_bits[3];

	u_char str[8] = "";
	str[0] = '\0';
	str[1] = '\0';
	str[2] = '\0';
	str[3] = '\0';

	int c = 7;
	for(int i = 4; i <= 7; i++){
		str[i] = fixed_header_bits[c];
		c--;
	}

	int control_pkt_type = str2int(str);

	switch (control_pkt_type){
		case 0:
			myprintf("RESERVED |");
			break;
		case 1:
			myprintf("CONNECT |");
			break;
		case 2:
			myprintf("CONNACK |");
			break;
		case 3:
			myprintf("PUBLISH |");
			break;
		case 4:
			myprintf("PUBACK |");
			break;
		case 5:
			myprintf("PUBREC |");
			break;
		case 6:
			myprintf("PUBREL |");
			break;
		case 7:
			myprintf("PUBCOMP |");
			break;
		case 8:
			myprintf("SUBSCRIBE |");
            fixed_header = *(p+1);
            unsigned char fixed_header_bits2[7];
            bits_from(fixed_header_bits2,fixed_header);

            int remaininig_length = str2int(fixed_header_bits2);
            int digit = 0;
            //int x = remaininig_length;
            /*encoding
             * do {
                digit = remaininig_length % 128;
                remaininig_length = remaininig_length / 128;
                if (remaininig_length > 0) {
                    digit = digit | 0x80;
                }
            }
            while (remaininig_length >0);*/
            int value =0;
            int multiplier = 1;
            do{
                digit = str2int(remaininig_length);
                value += (digit & 127) * multiplier;
                multiplier *= 128;
            }
            while ((digit & 128) !=0);

            myprintf("Remaininig length: %d|\n", value);

            fixed_header = *(p+1);
            bits_from(fixed_header_bits2,fixed_header);


            char QoS[3];
            QoS[0] = QoS1;
            QoS[0] = QoS2;

            char test[3] = {'\0','\001'};
            if(strcmp(QoS, test) == 0){
                myprintf("Remaininig length: %d|", ID_lsb);
            }

            int ID_msb = str2int(fixed_header_bits2);
            myprintf("Remaininig length: %d|", ID_msb);

            fixed_header = *(p+1);
            bits_from(fixed_header_bits2,fixed_header);
            int ID_lsb = str2int(fixed_header_bits2);
            myprintf("Remaininig length: %d|", ID_lsb);

			break;
		case 9:
			myprintf("SUBACK |");
			break;
		case 10:
			myprintf("UNSUBSCRIBE |");
			break;
		case 11:
			myprintf("UNSUBACK |");
			break;
		case 12:
			myprintf("PINGREQ |");
			break;
		case 13:
			myprintf("PINGRESP |");
			break;
		case 14:
			myprintf("DISCONNECT |");
			break;
		case 15:
			myprintf("RESERVED |");
			break;

	}

    for (i = 1; i <= len; i++) {
        if (isprint(*p))myprintf("%c", *p);
        else myprintf(".");
        if (isascii(*p))fprintf(mem, "%c", *p);
        else fprintf(mem, ".");
        p++;
        if ((i % 70) == 0)myprintf("\n     |");
    }
    myprintf("\n");
    fflush(mem);
    decoded = 1;
}
