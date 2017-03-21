#include "my.h"
#include <string.h>
#include <ctype.h>


int GetBit(u_char byte, int n){
    return (byte & (1<<n)) != 0 ? 1 : 0;
}

void reverse_array(u_char *pointer, int n)
{
    u_char *s;
    int c, d;

    s = (u_char*)malloc(sizeof(u_char)*n);

    if( s == NULL )
        exit(EXIT_FAILURE);

    for ( c = n - 1, d = 0 ; c >= 0 ; c--, d++ )
        *(s+d) = *(pointer+c);

    for ( c = 0 ; c < n ; c++ )
        *(pointer+c) = *(s+c);

    free(s);
}



void liv7(u_int len, const u_char *p) {
    int i;

    if ((int) len <= 0)return;
    colore(5);

	// Lettura Fixed Header
	u_char fixed_header = *(p);
	unsigned char fixed_header_bits[8];
	bits_from(fixed_header_bits,fixed_header);

	char retain = fixed_header_bits[0];
	u_char fh_qos_c[2];
	sprintf(fh_qos_c, "%d%d",fixed_header_bits[1],fixed_header_bits[2]);
	int fh_qos = str2int(fh_qos_c);
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

	myprintf("MQTT\n");
	myprintf("\tFixed Headers:\n");
	myprintf("\t\tControl Packet Type: %d\n",control_pkt_type);
	myprintf("\t\tDup: %d\n",dup);
	myprintf("\t\tQoS: %d\n",fh_qos);
	myprintf("\t\tRetain: %d\n",retain);

	switch (control_pkt_type){
		case 0:
			myprintf("RESERVED |");
			break;
		case 1:
			myprintf("\tCONNECT\n");
			//fixed_header = *(p+1);

			/*
			unsigned char fixed_header_bits2[8];
			bits_from(fixed_header_bits2,fixed_header);

			unsigned char more = fixed_header_bits2[7]; //c'è un altro byte di len

			unsigned char temp[7];
			memcpy(temp,fixed_header_bits2,sizeof(fixed_header_bits2)-1);

            reverse_array(temp, sizeof(temp));

			int remaining_length = str2int(temp);
			int digit = 0;

			int value =0;
			int multiplier = 1;
			do{
				digit = remaining_length;
				value += (digit & 127) * multiplier;
				multiplier *= 128;
			}
			while ((digit & 128) !=0);*/
			int k = 1;
			int multiplier = 1;
			int value = 0;
			u_char encodedByte;
			do {
				u_char encodedByte = *(p+k);
				value += (encodedByte &	127) * multiplier;
				multiplier *= 128;
				k++;

			} while ((encodedByte & 128) != 0);

			myprintf("\tRemaininig length: %d\n", value);

			//Lunghezza MSB e LSB dei restanti header
			unsigned char variable_headers_length_msb[8];
			bits_from(variable_headers_length_msb,*(p+3));
			unsigned char variable_headers_length_lsb[8];
			bits_from(variable_headers_length_lsb,*(p+4));

			unsigned char variable_headers_length[16];

			//u_char rev_msb[8];
			//u_char rev_lsb[8];

            reverse_array(variable_headers_length_msb,sizeof(variable_headers_length_msb));
            reverse_array(variable_headers_length_lsb,sizeof(variable_headers_length_lsb));

			memcpy(variable_headers_length,variable_headers_length_msb, sizeof(variable_headers_length_msb));
			memcpy(variable_headers_length + 8,variable_headers_length_lsb, sizeof(variable_headers_length_lsb));

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
			//u_char rev_pvm[8];
			reverse_array(pvn_bits,sizeof(pvn_bits));
			int pvm = str2int(pvn_bits);
			myprintf("\tProtocol Version Number: %d\n",pvm);
			buffer_offset++;

			// Connect Flags
			u_char cf_bits[8];
			bits_from(cf_bits,*(p+buffer_offset));

			u_char qos_c[2];
			sprintf(qos_c, "%d%d",cf_bits[3],cf_bits[4]);
			int qos = str2int(qos_c);
			int clean_session = cf_bits[1]; //se è 1 non si manda nel payload il client identifier
			int will_flag = cf_bits[2];
			int will_retain = cf_bits[5];
			int password = cf_bits[6];
			int username = cf_bits[7];
			myprintf("\t\tReserved: %d\n",cf_bits[0]);
			myprintf("\t\tClean Session: %d\n",clean_session);
			myprintf("\t\tWill Flag: %d\n",will_flag);
			myprintf("\t\tQoS: %d\n",qos);
			myprintf("\t\tWill Retain: %d\n",will_retain);
			myprintf("\t\tPassword: %d\n", password);
			myprintf("\t\tUsername: %d\n", username);
			buffer_offset++;

			// Keep Alive Timer
			unsigned char keep_alive_timer_msb[8];
			bits_from(keep_alive_timer_msb,*(p+buffer_offset));
			buffer_offset++;
			unsigned char keep_alive_timer_lsb[8];
			bits_from(keep_alive_timer_lsb,*(p+buffer_offset));
			buffer_offset++;

			unsigned char keep_alive[16];

			//u_char rev_ka_msb[8];
			//u_char rev_ka_lsb[8];

			reverse_array(keep_alive_timer_msb,sizeof(keep_alive_timer_msb));
			reverse_array(keep_alive_timer_lsb,sizeof(keep_alive_timer_lsb));

			memcpy(keep_alive,keep_alive_timer_msb, sizeof(keep_alive_timer_msb));
			memcpy(keep_alive + 8,keep_alive_timer_lsb, sizeof(keep_alive_timer_lsb));

			int keep_alive_timer = str2int16(keep_alive);
			myprintf("\tKeep Alive Timer: %d\n", keep_alive_timer);

			// Payload
			if (clean_session == 0) //c'è un client identifier
			{

			}

			if(will_flag == 1) // se will flag è 1 ci sono will topic e will message
			{

			}

			if(username == 1) // se username è 1 c'è uno username
			{

			}

			if(password == 1) // se password è 1 c'è una password
			{

			}


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
			myprintf("\tSUBSCRIBE \n");
            //fixed_header = *(p+1);

            /*fixed_header_bits2[8];
            bits_from(fixed_header_bits2,fixed_header);

            int prova = GetBit(fixed_header_bits2, 1);

            more = fixed_header_bits2[7]; //c'è un altro byte di len

            free(prova);

            temp[7];
            memcpy(temp,fixed_header_bits2,sizeof(fixed_header_bits2)-1);

            //reversed[7];

            //reverse(temp,reversed);

			int remaining_length2 = str2int(temp);
            digit = 0;

            value =0;
            multiplier = 1;
            do{
                digit = remaining_length2;
                value += (digit & 127) * multiplier;
                multiplier *= 128;
            }
            while ((digit & 128) !=0);
            */
			k = 1;
			multiplier = 1;
			value = 0;

			do {
				u_char encodedByte = (*p+k);
				value += (encodedByte &	127) * multiplier;
				multiplier *= 128;
				k++;

			} while ((encodedByte & 128) != 0);

            myprintf("\tRemaininig length: %d\n", value);

            myprintf("\tMessage Header:\n");

            //Lunghezza MSB e LSB dei restanti header
            unsigned char variable_headers_message_ID_msb[8];
            memset(variable_headers_message_ID_msb,'\000',8);
            bits_from(variable_headers_message_ID_msb,*(p+2));
            reverse_array(variable_headers_message_ID_msb, sizeof(variable_headers_message_ID_msb));




			//
			myprintf("ID MSB: ");
			myprintf("%d", variable_headers_message_ID_msb[0]);
			myprintf("%d", variable_headers_message_ID_msb[1]);
			myprintf("%d", variable_headers_message_ID_msb[2]);
			myprintf("%d", variable_headers_message_ID_msb[3]);
			myprintf("%d", variable_headers_message_ID_msb[4]);
			myprintf("%d", variable_headers_message_ID_msb[5]);
			myprintf("%d", variable_headers_message_ID_msb[6]);
			myprintf("%d\n", variable_headers_message_ID_msb[7]);
			//

            unsigned char variable_headers_message_ID_lsb[8];
            memset(variable_headers_message_ID_lsb,'\000',8);
            bits_from(variable_headers_message_ID_lsb,*(p+3));
			reverse_array(variable_headers_message_ID_lsb, sizeof(variable_headers_message_ID_lsb));

			//
			myprintf("ID LSB: ");
			myprintf("%d", variable_headers_message_ID_lsb[0]);
			myprintf("%d", variable_headers_message_ID_lsb[1]);
			myprintf("%d", variable_headers_message_ID_lsb[2]);
			myprintf("%d", variable_headers_message_ID_lsb[3]);
			myprintf("%d", variable_headers_message_ID_lsb[4]);
			myprintf("%d", variable_headers_message_ID_lsb[5]);
			myprintf("%d", variable_headers_message_ID_lsb[6]);
			myprintf("%d\n", variable_headers_message_ID_lsb[7]);
			//

            /*u_char rev_msb2[8];
            memset(rev_msb2,'\000',8);
            u_char rev_lsb2[8];
            memset(rev_lsb2,'\000',8);

            reverse(variable_headers_message_ID_msb,rev_msb2);
            reverse(variable_headers_message_ID_lsb,rev_lsb2);
             */

            unsigned char variable_headers_id[16];

            memcpy(variable_headers_id,variable_headers_message_ID_msb, sizeof(variable_headers_message_ID_msb));
            memcpy(variable_headers_id + 8,variable_headers_message_ID_lsb, sizeof(variable_headers_message_ID_lsb));


            int id = str2int16(variable_headers_id);
            int id1 = str2int(variable_headers_message_ID_msb);
            int id2 = str2int(variable_headers_message_ID_lsb);
            myprintf("\t\tMessage ID msb: %d\n", id1);
            myprintf("\t\tMessage ID lsb: %d\n", id2);
            myprintf("\t\tMessage ID: %d\n", id);
            /*fixed_header_bits2[8];
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
