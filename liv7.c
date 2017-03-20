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
			myprintf("CONNECT\n");
			fixed_header = *(p+1);

			unsigned char fixed_header_bits2[8];
			bits_from(fixed_header_bits2,fixed_header);

			unsigned char more = fixed_header_bits2[7]; //c'è un altro byte di len

			unsigned char temp[7];
			memcpy(temp,fixed_header_bits2,sizeof(fixed_header_bits2)-1);

			unsigned char reversed[7];

			reverse(temp,reversed);

			int remaininig_length = str2int(reversed);
			int digit = 0;

			int value =0;
			int multiplier = 1;
			do{
				digit = remaininig_length;
				value += (digit & 127) * multiplier;
				multiplier *= 128;
			}
			while ((digit & 128) !=0);

			myprintf("\tRemaininig length: %d\n", value);

			//Lunghezza MSB e LSB dei restanti header
			unsigned char variable_headers_length_msb[8];
			bits_from(variable_headers_length_msb,*(p+3));
			unsigned char variable_headers_length_lsb[8];
			bits_from(variable_headers_length_lsb,*(p+4));

			unsigned char variable_headers_length[16];

			u_char rev_msb[8];
			u_char rev_lsb[8];

			reverse(variable_headers_length_msb,rev_msb);
			reverse(variable_headers_length_lsb,rev_lsb);

			memcpy(variable_headers_length,rev_msb, sizeof(rev_msb));
			memcpy(variable_headers_length + 8,rev_lsb, sizeof(rev_lsb));

			int v_h_length = str2int(variable_headers_length);
			myprintf("\tVariable Headers length: %d\n", v_h_length);


			int buffer_offset = 4;
			// Prendo i variable headers
			for(int i=0; i<v_h_length;i++)
			{
				myprintf("\t\tVariable Header %d: %c\n", i+1, *(p+buffer_offset));

				buffer_offset++;
			}

			// Protocol Version Number
			u_char pvn_bits[8];
			bits_from(pvn_bits,*(p+buffer_offset));
			u_char rev_pvm[8];
			reverse(pvn_bits,rev_pvm);
			int pvm = str2int(rev_pvm);
			myprintf("\tProtocol Version Number: %d\n",pvm);
			buffer_offset++;

			// Connect Flags
			u_char cf_bits[8];
			bits_from(cf_bits,*(p+buffer_offset));

			u_char qos_c[2];
			sprintf(qos_c, "%d%d",cf_bits[3],cf_bits[4]);
			int qos = str2int(qos_c);
			myprintf("\t\tReserved: %d\n",cf_bits[0]);
			myprintf("\t\tClean Session: %d\n",cf_bits[1]);
			myprintf("\t\tWill Flag: %d\n",cf_bits[2]);
			myprintf("\t\tQoS: %d\n",qos);
			myprintf("\t\tWill Retain: %d\n",cf_bits[5]);
			myprintf("\t\tPassword: %d\n",cf_bits[6]);
			myprintf("\t\tUsername: %d\n",cf_bits[7]);
			buffer_offset++;

			// Keep Alive Timer
			unsigned char keep_alive_timer_msb[8];
			bits_from(keep_alive_timer_msb,*(p+buffer_offset));
			buffer_offset++;
			unsigned char keep_alive_timer_lsb[8];
			bits_from(keep_alive_timer_lsb,*(p+buffer_offset));
			buffer_offset++;

			unsigned char keep_alive[16];

			u_char rev_ka_msb[8];
			u_char rev_ka_lsb[8];

			reverse(keep_alive_timer_msb,rev_ka_msb);
			reverse(keep_alive_timer_lsb,rev_ka_lsb);

			memcpy(keep_alive,rev_ka_msb, sizeof(rev_ka_msb));
			memcpy(keep_alive + 8,rev_ka_lsb, sizeof(rev_ka_lsb));

			int keep_alive_timer = str2int(keep_alive);
			myprintf("\tKeep Alive Timer: %d\n", keep_alive_timer);

			// Payload

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

            /*unsigned char fixed_header_bits2[8];
			bits_from(fixed_header_bits2,fixed_header);

			unsigned char more = fixed_header_bits2[7]; //c'è un altro byte di len

			unsigned char lel[7];
			memcpy(lel,fixed_header_bits2,sizeof(fixed_header_bits2)-1);

			unsigned char reversed[7];

			reverse(lel,reversed);

            int remaininig_length = str2int(reversed);
            int digit = 0;

            int value =0;
            int multiplier = 1;
            do{
                digit = remaininig_length;
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
                //myprintf("Remaininig length: %d|", ID_lsb);
            }

            int ID_msb = str2int(fixed_header_bits2);
            myprintf("Remaininig length: %d|", ID_msb);

            fixed_header = *(p+1);
            bits_from(fixed_header_bits2,fixed_header);
            int ID_lsb = str2int(fixed_header_bits2);
            myprintf("Remaininig length: %d|", ID_lsb);*/

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
