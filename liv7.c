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
	u_char fh_qos_c[2] = {fixed_header_bits[2],fixed_header_bits[1]};
	int fh_qos = str2int2(fh_qos_c);
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

	int k = 1;
	int multiplier = 1;
	int remaining_length = 0;
	u_char encodedByte;
	do {
		encodedByte = *(p+k);
		remaining_length += (encodedByte &	127) * multiplier;
		multiplier *= 128;
		k++;

	} while ((encodedByte & 128) != 0);

	if(remaining_length + k != len)
	{
		myprintf("APPL |");
		for(i=1;i<=len;i++){
			if(isprint(*p))myprintf("%c",*p);
			else myprintf(".");
			if(isascii(*p))fprintf(mem,"%c",*p);
			else fprintf(mem,".");
			p++;
			if((i%70)==0)myprintf("\n     |");
		}
		myprintf("\n");
		fflush(mem);
	}else{
		myprintf("MQTT\n");
		myprintf("\tFixed Headers:\n");
		myprintf("\t\tControl Packet Type: %d\n",control_pkt_type);

		switch (control_pkt_type){
			case 0:
				myprintf("\tRESERVED\n");
				break;
			case 1:
				myprintf("\t\tReserved: %d\n",dup);
				myprintf("\t\tReserved: %d\n",fh_qos_c[0]);
				myprintf("\t\tReserved: %d\n",fh_qos_c[1]);
				myprintf("\t\tReserved: %d\n",retain);
				myprintf("\tRemaininig length: %d\n", remaining_length);

				myprintf("\tCONNECT\n");

				(*p--);

				//Lunghezza MSB e LSB dei restanti header
				unsigned char variable_headers_length_msb[8];
				bits_from(variable_headers_length_msb,*(p+3));
				unsigned char variable_headers_length_lsb[8];
				bits_from(variable_headers_length_lsb,*(p+4));

				unsigned char variable_headers_length[16];

				reverse_array(variable_headers_length_msb,sizeof(variable_headers_length_msb));
				reverse_array(variable_headers_length_lsb,sizeof(variable_headers_length_lsb));

				memcpy(variable_headers_length,variable_headers_length_msb, sizeof(variable_headers_length_msb));
				memcpy(variable_headers_length + 8,variable_headers_length_lsb, sizeof(variable_headers_length_lsb));

				int v_h_length = str2int16(variable_headers_length);
				myprintf("\tVariable Headers length: %d\n", v_h_length);


				int buffer_offset = 5;
				// Prendo i variable headers
				for(int i=0; i<v_h_length;i++)
				{
					myprintf("\t\tVariable Header %d: %c\n", i+1, *(p+buffer_offset));

					buffer_offset++;
				}

				// Protocol Version Number
				u_char pvn_bits[8];
				bits_from(pvn_bits,*(p+buffer_offset));
				reverse_array(pvn_bits,sizeof(pvn_bits));
				int pvm = str2int(pvn_bits);
				myprintf("\tProtocol Version Number: %d\n",pvm);
				buffer_offset++;

				// Connect Flags
				u_char cf_bits[8];
				bits_from(cf_bits,*(p+buffer_offset));

				u_char qos_c[2] = {cf_bits[3],cf_bits[4]};
				int qos = str2int2(qos_c);
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

				unsigned char keep_alive[16];

				reverse_array(keep_alive_timer_msb,sizeof(keep_alive_timer_msb));
				reverse_array(keep_alive_timer_lsb,sizeof(keep_alive_timer_lsb));

				memcpy(keep_alive,keep_alive_timer_msb, sizeof(keep_alive_timer_msb));
				memcpy(keep_alive + 8,keep_alive_timer_lsb, sizeof(keep_alive_timer_lsb));

				int keep_alive_timer = str2int16(keep_alive);
				myprintf("\tKeep Alive Timer: %d\n", keep_alive_timer);
				buffer_offset++;

				// Payload
				//Client identifier
				unsigned char client_id_length_msb[8];
				bits_from(client_id_length_msb,*(p+buffer_offset));
				buffer_offset++;
				unsigned char client_id_length_lsb[8];
				bits_from(client_id_length_lsb,*(p+buffer_offset));

				unsigned char client_id_length[16];

				reverse_array(client_id_length_msb,sizeof(client_id_length_msb));
				reverse_array(client_id_length_lsb,sizeof(client_id_length_lsb));

				memcpy(client_id_length,client_id_length_msb, sizeof(client_id_length_msb));
				memcpy(client_id_length + 8,client_id_length_lsb, sizeof(client_id_length_lsb));

				int clt_id_len = str2int16(client_id_length);
				myprintf("\tClient Id length: %d\n", clt_id_len);

				// Client ID
				buffer_offset++;
				myprintf("\tClient Id: ");

				for(int i=0; i<clt_id_len;i++)
				{
					myprintf("%c", *(p+buffer_offset));
					buffer_offset++;
				}
				myprintf("\n");


				if(will_flag == 1) // se will flag è 1 ci sono will topic e will message
				{
					// Will topic length
					unsigned char will_topic_length_msb[8];
					bits_from(will_topic_length_msb,*(p+buffer_offset));
					buffer_offset++;
					unsigned char will_topic_length_lsb[8];
					bits_from(will_topic_length_lsb,*(p+buffer_offset));

					unsigned char will_topic_length[16];

					reverse_array(will_topic_length_msb,sizeof(will_topic_length_msb));
					reverse_array(will_topic_length_lsb,sizeof(will_topic_length_lsb));

					memcpy(will_topic_length,will_topic_length_msb, sizeof(will_topic_length_msb));
					memcpy(will_topic_length + 8,will_topic_length_lsb, sizeof(will_topic_length_lsb));

					int will_topic_len = str2int16(will_topic_length);
					myprintf("\tWill Topic length: %d\n", will_topic_len);

					// Will Topic
					buffer_offset++;
					myprintf("\tWill Topic: ", will_topic_len);
					for(int i=0; i<will_topic_len;i++)
					{
						myprintf("%c", *(p+buffer_offset));
						buffer_offset++;
					}
					myprintf("\n");



					// Will Message length
					unsigned char will_message_length_msb[8];
					bits_from(will_message_length_msb,*(p+buffer_offset));
					buffer_offset++;
					unsigned char will_message_length_lsb[8];
					bits_from(will_message_length_lsb,*(p+buffer_offset));

					unsigned char will_message_length[16];

					reverse_array(will_message_length_msb,sizeof(will_message_length_msb));
					reverse_array(will_message_length_lsb,sizeof(will_message_length_lsb));

					memcpy(will_message_length,will_message_length_msb, sizeof(will_message_length_msb));
					memcpy(will_message_length + 8,will_message_length_lsb, sizeof(will_message_length_lsb));

					int will_message_len = str2int16(will_message_length);
					myprintf("\tWill Message length: %d\n", will_message_len);

					// Will Message
					buffer_offset++;
					myprintf("\tWill Message: ", will_message_len);
					for(int i=0; i<will_message_len;i++)
					{
						myprintf("%c", *(p+buffer_offset));
						buffer_offset++;
					}
					myprintf("\n");
				}

				if(username == 1) // se username è 1 c'è uno username
				{

					// Username length
					unsigned char username_length_msb[8];
					bits_from(username_length_msb,*(p+buffer_offset));
					buffer_offset++;
					unsigned char username_length_lsb[8];
					bits_from(username_length_lsb,*(p+buffer_offset));

					unsigned char username_length[16];

					reverse_array(username_length_msb,sizeof(username_length_msb));
					reverse_array(username_length_lsb,sizeof(username_length_lsb));

					memcpy(username_length,username_length_msb, sizeof(username_length_msb));
					memcpy(username_length + 8,username_length_lsb, sizeof(username_length_lsb));

					int username_len = str2int16(username_length);
					myprintf("\tUsername length: %d\n", username_len);

					// Username
					buffer_offset++;
					myprintf("\tUsername:", username_len);
					for(int i=0; i<username_len;i++)
					{
						myprintf("%c", *(p+buffer_offset));
						buffer_offset++;
					}
					myprintf("\n");
				}

				if(password == 1) // se password è 1 c'è una password
				{
					// Username length
					unsigned char password_length_msb[8];
					bits_from(password_length_msb,*(p+buffer_offset));
					buffer_offset++;
					unsigned char password_length_lsb[8];
					bits_from(password_length_lsb,*(p+buffer_offset));

					unsigned char password_length[16];

					reverse_array(password_length_msb,sizeof(password_length_msb));
					reverse_array(password_length_lsb,sizeof(password_length_lsb));

					memcpy(password_length,password_length_msb, sizeof(password_length_msb));
					memcpy(password_length + 8,password_length_lsb, sizeof(password_length_lsb));

					int password_len = str2int16(password_length);
					myprintf("\tPassword length: %d\n", password_len);

					// Username
					buffer_offset++;
					myprintf("\tPassword:", password_len);
					for(int i=0; i<password_len;i++)
					{
						myprintf("%c", *(p+buffer_offset));
						buffer_offset++;
					}
					myprintf("\n");
				}


				break;
			case 2:
				myprintf("\t\tReserved: %d\n",dup);
				myprintf("\t\tReserved: %d\n",fh_qos_c[0]);
				myprintf("\t\tReserved: %d\n",fh_qos_c[1]);
				myprintf("\t\tReserved: %d\n",retain);
				myprintf("\tRemaining length: %d\n", remaining_length);
				myprintf("\tCONNACK\n");

				// Connection Ack Flags
				unsigned char connack_flags[8];
				bits_from(connack_flags,*(p+2));
				//reverse_array(connack_flags,sizeof(connack_flags));
				myprintf("\tSession Present Flag: %d\n",connack_flags[0]);

				myprintf("\tConnection Acknowledge Flags:\n");

				for (i=1;i<=7;i++)
				{
					myprintf("\t\tReserved: %d\n",connack_flags[i]);
				}

				unsigned char connection_return_code[8];
				bits_from(connection_return_code,*(p+3));
				reverse_array(connection_return_code,sizeof(connection_return_code));
				int conn_ret_code = str2int(connection_return_code);

				switch(conn_ret_code)
				{
					case 0:
						myprintf("\tConnection Return Code: 0 (ACCEPTED)\n");
						break;
					case 1:
						myprintf("\tConnection Return Code: 1 (REFUSED, UNACCEPTABLE PROTOCOL VERSION)\n");
						break;
					case 2:
						myprintf("\tConnection Return Code: 2 (REFUSED, IDENTIFIER REJECTED)\n");
						break;
					case 3:
						myprintf("\tConnection Return Code: 3 (REFUSED, SERVER UNAVAILABLE)\n");
						break;
					case 4:
						myprintf("\tConnection Return Code: 4 (REFUSED, BAD USERNAME OR PASSWORD)\n");
						break;
					case 5:
						myprintf("\tConnection Return Code: 5 (REFUSED, NOT AUTHORIZED)\n");
						break;
					default:
						myprintf("\tUnknown Connection Return Code\n");
						break;
				}

				break;
			case 3:
				myprintf("\t\tDup: %d\n",dup);
				myprintf("\t\tQoS: %d\n",fh_qos);
				myprintf("\t\tRetain: %d\n",retain);
				myprintf("\tRemaining length: %d\n", remaining_length);
				myprintf("\tPUBLISH\n");

				int x = 1;
				int multi = 1;
				int val = 0;
				u_char enc_Byte;
				do
				{
					enc_Byte = *(p+x);
					val += (enc_Byte &	127) * multi;
					multi *= 128;
					x++;
				}
				while ((enc_Byte & 128) != 0);
				(*p--);
				//Print the result

				//Lunghezza MSB e LSB dei restanti header
				unsigned char var_headers_length_msb[8];
				bits_from(var_headers_length_msb,*(p+3));
				unsigned char var_headers_length_lsb[8];
				bits_from(var_headers_length_lsb,*(p+4));

				unsigned char var_headers_length[16];

				reverse_array(var_headers_length_msb,sizeof(var_headers_length_msb));
				reverse_array(var_headers_length_lsb,sizeof(var_headers_length_lsb));

				memcpy(var_headers_length,var_headers_length_msb, sizeof(var_headers_length_msb));
				memcpy(var_headers_length + 8,var_headers_length_lsb, sizeof(var_headers_length_lsb));

				int var_h_length = str2int16(var_headers_length);
				myprintf("\t\tVariable Headers length: %d\n", var_h_length);

				//topic name
				int buff_offset = 5;
				myprintf("\t\tTopic Name: ");
				for(int i = 0; i < var_h_length; i++)
				{
					myprintf("%c", *(p+buff_offset));
					buff_offset++;
				}
				myprintf("\n");

				//TODO: Packet_ID è un campo che esiste solo se QoS è > 0..Dovrebbe andare
				if(fh_qos > 0)
				{
					unsigned char pk_ID_msb[8];
					bits_from(pk_ID_msb,*(p+buff_offset));
					buff_offset ++;
					unsigned char pk_ID_lsb[8];
					bits_from(pk_ID_lsb,*(p+buff_offset));
					buff_offset++;

					unsigned char pk_ID_length[16];

					reverse_array(pk_ID_msb,sizeof(pk_ID_msb));
					reverse_array(pk_ID_lsb,sizeof(pk_ID_lsb));

					memcpy(pk_ID_length,pk_ID_msb, sizeof(pk_ID_msb));
					memcpy(pk_ID_length + 8,pk_ID_lsb, sizeof(pk_ID_lsb));

					int pk_ID = str2int16(pk_ID_length);

					myprintf("\t\tPacket_ID: %d\n", pk_ID);
				}

				//Stampo il Payload
				myprintf("\t\tPayload: ");
				for(int i = buff_offset; i <=len; i++)
				{
					myprintf("%c", *(p + buff_offset));
					buff_offset ++;
				}

				break;

			case 4:
				myprintf("\t\tReserved: %d\n",dup);
				myprintf("\t\tReserved: %d\n",fh_qos_c[0]);
				myprintf("\t\tReserved: %d\n",fh_qos_c[1]);
				myprintf("\t\tReserved: %d\n",retain);
				myprintf("\tRemaining length: %d\n", remaining_length);
				myprintf("\tPUBACK\n");

                unsigned char p_ACK_msb[8];
                bits_from(p_ACK_msb,*(p+2));
                unsigned char p_ACK_lsb[8];
                bits_from(p_ACK_lsb,*(p+3));

                unsigned char p_ACK_length[16];

                reverse_array(p_ACK_msb,sizeof(p_ACK_msb));
                reverse_array(p_ACK_lsb,sizeof(p_ACK_lsb));

                memcpy(p_ACK_length,p_ACK_msb, sizeof(p_ACK_msb));
                memcpy(p_ACK_length + 8,p_ACK_lsb, sizeof(p_ACK_lsb));

                int pk_AK = str2int16(p_ACK_length);

                myprintf("\t\tPacket ID ACK: %d", pk_AK);

				break;

            case 5:
				myprintf("\t\tReserved: %d\n",dup);
				myprintf("\t\tReserved: %d\n",fh_qos_c[0]);
				myprintf("\t\tReserved: %d\n",fh_qos_c[1]);
				myprintf("\t\tReserved: %d\n",retain);
				myprintf("\tRemaining length: %d\n", remaining_length);
				myprintf("\tPUBREC\n");

                unsigned char p_REC_msb[8];
                bits_from(p_REC_msb,*(p+2));
                unsigned char p_REC_lsb[8];
                bits_from(p_REC_lsb,*(p+3));

                unsigned char p_REC_length[16];

                reverse_array(p_REC_msb,sizeof(p_REC_msb));
                reverse_array(p_REC_lsb,sizeof(p_REC_lsb));

                memcpy(p_REC_length,p_REC_msb, sizeof(p_REC_msb));
                memcpy(p_REC_length + 8,p_REC_lsb, sizeof(p_REC_lsb));

                int pk_REC = str2int16(p_REC_length);

                myprintf("\t\tPacket ID REC: %d", pk_REC);

				break;
			case 6:
				myprintf("\t\tReserved: %d\n",dup);
				myprintf("\t\tReserved: %d\n",fh_qos_c[0]);
				myprintf("\t\tReserved: %d\n",fh_qos_c[1]);
				myprintf("\t\tReserved: %d\n",retain);
				myprintf("\tRemaining length: %d\n", remaining_length);
				myprintf("\tPUBREL\n");

                unsigned char p_REL_msb[8];
                bits_from(p_REL_msb,*(p+2));
                unsigned char p_REL_lsb[8];
                bits_from(p_REL_lsb,*(p+3));

                unsigned char p_REL_length[16];

                reverse_array(p_REL_msb,sizeof(p_REL_msb));
                reverse_array(p_REL_lsb,sizeof(p_REL_lsb));

                memcpy(p_REL_length,p_REL_msb, sizeof(p_REL_msb));
                memcpy(p_REL_length + 8,p_REL_lsb, sizeof(p_REL_lsb));

                int pk_REL = str2int16(p_REL_length);

                myprintf("\t\tPacket ID REL: %d", pk_REL);

				break;
			case 7:
				myprintf("\t\tReserved: %d\n",dup);
				myprintf("\t\tReserved: %d\n",fh_qos_c[0]);
				myprintf("\t\tReserved: %d\n",fh_qos_c[1]);
				myprintf("\t\tReserved: %d\n",retain);
				myprintf("\tRemaining length: %d\n", remaining_length);
				myprintf("\tPUBCOMP\n");

                unsigned char p_COMP_msb[8];
                bits_from(p_COMP_msb,*(p+2));
                unsigned char p_COMP_lsb[8];
                bits_from(p_COMP_lsb,*(p+3));

                unsigned char p_COMP_length[16];

                reverse_array(p_COMP_msb,sizeof(p_COMP_msb));
                reverse_array(p_COMP_lsb,sizeof(p_COMP_lsb));

                memcpy(p_COMP_length,p_COMP_msb, sizeof(p_COMP_msb));
                memcpy(p_COMP_length + 8,p_COMP_lsb, sizeof(p_COMP_lsb));

                int pk_COMP = str2int16(p_COMP_length);

                myprintf("\t\tPacket ID COMP: %d", pk_COMP);

				break;

            case 8:
				myprintf("\t\tReserved: %d\n",dup);
				myprintf("\t\tReserved: %d\n",fh_qos_c[0]);
				myprintf("\t\tReserved: %d\n",fh_qos_c[1]);
				myprintf("\t\tReserved: %d\n",retain);
				myprintf("\tRemaining length: %d\n", remaining_length);
				myprintf("\tSUBSCRIBE\n");

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
				myprintf("\t\tReserved: %d\n",dup);
				myprintf("\t\tReserved: %d\n",fh_qos_c[0]);
				myprintf("\t\tReserved: %d\n",fh_qos_c[1]);
				myprintf("\t\tReserved: %d\n",retain);
				myprintf("\tRemaining length: %d\n", remaining_length);
				myprintf("\tSUBACK\n");
				break;
			case 10:
				myprintf("\t\tReserved: %d\n",dup);
				myprintf("\t\tReserved: %d\n",fh_qos_c[0]);
				myprintf("\t\tReserved: %d\n",fh_qos_c[1]);
				myprintf("\t\tReserved: %d\n",retain);
				myprintf("\tRemaining length: %d\n", remaining_length);
				myprintf("\tUNSUBSCRIBE\n");
				break;
			case 11:
				myprintf("\t\tReserved: %d\n",dup);
				myprintf("\t\tReserved: %d\n",fh_qos_c[0]);
				myprintf("\t\tReserved: %d\n",fh_qos_c[1]);
				myprintf("\t\tReserved: %d\n",retain);
				myprintf("\tRemaining length: %d\n", remaining_length);
				myprintf("\tUNSUBACK\n");
				break;
			case 12:
				myprintf("\t\tReserved: %d\n",dup);
				myprintf("\t\tReserved: %d\n",fh_qos_c[0]);
				myprintf("\t\tReserved: %d\n",fh_qos_c[1]);
				myprintf("\t\tReserved: %d\n",retain);
				myprintf("\tRemaining length: %d\n", remaining_length);
				myprintf("\tPINGREQ\n");
				break;
			case 13:
				myprintf("\t\tReserved: %d\n",dup);
				myprintf("\t\tReserved: %d\n",fh_qos_c[0]);
				myprintf("\t\tReserved: %d\n",fh_qos_c[1]);
				myprintf("\t\tReserved: %d\n",retain);
				myprintf("\tRemaining length: %d\n", remaining_length);
				myprintf("\tPINGRESP\n");
				break;
			case 14:
				myprintf("\t\tReserved: %d\n",dup);
				myprintf("\t\tReserved: %d\n",fh_qos_c[0]);
				myprintf("\t\tReserved: %d\n",fh_qos_c[1]);
				myprintf("\t\tReserved: %d\n",retain);
				myprintf("\tRemaining length: %d\n", remaining_length);
				myprintf("\tDISCONNECT\n");
				break;
			case 15:
				myprintf("\tRESERVED\n");
				break;
			default:
				myprintf("\tUNKNOWN CONTROL PACKET TYPE\n");
				break;
		}
/*
		for (i = 1; i <= len; i++) {
			if (isprint(*p))myprintf("%c", *p);
			else myprintf(".");
			if (isascii(*p))fprintf(mem, "%c", *p);
			else fprintf(mem, ".");
			p++;
			if ((i % 70) == 0)myprintf("\n     |");
		}*/
		myprintf("\n");
		fflush(mem);
		decoded = 1;
	}
}
