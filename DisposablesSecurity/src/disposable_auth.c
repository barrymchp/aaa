/*
 * disposable_auth.c
 *
 * Created: 7/13/16 5:48:26 PM
 *  Author: sanchezoscar
 */ 

#include <asf.h>
#include <string.h>
#include <stdio.h>
#include "cryptoauthlib.h"
#include "sio2host.h"
#include "conf_sio2host.h"
#include "stdio_serial.h"
#include "basic\atca_helpers.h"
#include "disposable_auth.h"
#include "main.h"


/*************************GLOBAL VARIABLES**********************************/
/*Used to Verify I2C address*/
uint8_t i2cHost = DERIVED_KEY_HOST_I2C_ADDR;
uint8_t i2cClient = DERIVED_KEY_CLIENT_I2C_ADDR;


struct client_auth_t client_auth = {
	/*Refer to data sheet under GenDig Command Other Data*/
	.gen_dig_other_data = {
		0x1C,	//Derive Key Opcode
		0x04,	//Temp Key Flag Value
		0x01,	//Slot containing diversified key
	    0x00	//0x00
		},	
	/*Refer to data sheet under CheckMaC Command Other Data. Client Serial Number data
	  will be added at moment of constructing CheckMac command in the demo code*/
	.checkmac_other_data = {
		0x08, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00
		}
};

struct client_auth_t client_auth_consumption_count = {
	/*Refer to data sheet under GenDig Command Other Data*/
	.gen_dig_other_data = {
		0x1C,	//Derive Key Opcode
		0x04,	////Temp Key Flag Value
		0x07,	//Slot containing diversified key for consumption counting
	    0x00	// 0x00
		},	
	/*Refer to data sheet under CheckMaC Command Other Data. Client Serial Number data
	  will be added at moment of constructing CheckMac command in the demo code*/
	.checkmac_other_data = {
		0x08, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00,
		0x00
		}
};




void authenticate_client(void)
{//
	char disp_str[1500];
	int disp_size = sizeof(disp_str);
	uint8_t return_code = ATCA_SUCCESS;
	uint8_t config_zone_block = 1;
	uint8_t config_zone_offset = 5;
	uint8_t config_index = 0;
	
	/*HOST AUTHENTICATES A CLIENT DEVERSIFIED KEY USING ROOT KEY*/
	do{
		/*Set HOST I2C address*/
		cfg_sha204a_i2c_default.atcai2c.slave_address = DERIVED_KEY_HOST_I2C_ADDR;
		return_code = atcab_init( &cfg_sha204a_i2c_default );
		if (return_code != ATCA_SUCCESS)
		{
			printf("Not Communicating check I2C address\r\n");
			break;
		}else
		{
			printf("HOST \r\n");
			printf("Set HOST I2C address\r\n");
		}
		
		/*HOST GET RANDOM NUMBER*/
		return_code = atcab_random(client_auth.host_random);
		if (return_code != ATCA_SUCCESS)
		{
			printf("Random Number Generation failed\r\n");
			break;
		}else
		{
			disp_size = sizeof(disp_str);
			atcab_bin2hex( client_auth.host_random, sizeof(client_auth.host_random), disp_str, &disp_size);
			printf("HOST: Sending Random Challenge to Client:\n\r\n%s\r\n", disp_str);
			printf("\r\n");
		}
		
		/*Set client configured I2C address*/
		cfg_sha204a_i2c_default.atcai2c.slave_address = DERIVED_KEY_CLIENT_I2C_ADDR;
		return_code = atcab_init( &cfg_sha204a_i2c_default );
		if (return_code != ATCA_SUCCESS)
		{
			printf("Not Communicating check I2C address\r\n");
			break;
		}else
		{
			printf("CLIENT\r\n");
			printf("Set CLIENT I2C address\r\n");
			printf("\r\n");
		}
		
		/*CLIENT GENERATE MAC (SHA 256 HASH) ON CLIENT USING DERIVED KEY IN SLOT 1 AND CHALANGE (RANDOM NUMBER)*/
		/*CLIENT CALCULATE MAC FROM DERIVED KEY IN SLOT 0x01 AND RANDOM CHALLANEGE FROM HOST*/
		printf("CLIENT: Obtaining MAC for the Diversified Key in Slot 1\r\n");
		return_code = atcab_mac( CLIENT_MODE_FOR_CAL_MAC, CLIENT_DERIVE_KEY_SLOT_NO_CONSUMTION_COUNTING, client_auth.host_random, client_auth.sha_256_MAC );
		if (return_code	!= ATCA_SUCCESS)
		{
			printf("MAC failed\r\n");
		}
		else
		{
			disp_size = sizeof(disp_str);
			atcab_bin2hex( client_auth.sha_256_MAC,sizeof(client_auth.sha_256_MAC), disp_str, &disp_size);
			printf("Responding Challenge from HOST:\n\r\n%s\r\n", disp_str);
			printf("\r\n");
		}
		
		///*CLIENT Read Serial Number*/
		return_code = atcab_read_serial_number(client_auth.dev_serial);
		if (return_code != ATCA_SUCCESS)
		{
			printf("Read Serial Number failed\r\n");
			break;
		}else
		{
			disp_size = sizeof(disp_str);
			atcab_bin2hex( client_auth.dev_serial,sizeof(client_auth.dev_serial), disp_str, &disp_size);
			printf("CLIENT: Reading Client SerialNumber:\n\r\n%s\r\n", disp_str);
			printf("Sending to HOST\r\n");
			printf("\r\n");
		}
		
		
		

		
		/*Set HOST I2C address*/
		cfg_sha204a_i2c_default.atcai2c.slave_address = DERIVED_KEY_HOST_I2C_ADDR;
		return_code = atcab_init( &cfg_sha204a_i2c_default );
		if (return_code != ATCA_SUCCESS)
		{
			printf("Not Communicating check I2C address\r\n");
			break;
		}else
		{
			printf("HOST \r\n");
			printf("Set HOST I2C address\r\n");
			printf("\r\n");
		}
		
		///*HOST PAD SERIAL NUMBER-> SERIAL + PAD OF 7's TO FORM A 32BYTE TEMP KEY*/
		printf("HOST: Padding Serial Number from CLIENT with 0x77\r\n");
		
		// Set the pad bytes
		memset(&client_auth.tempkey[0], 0x77, ATCA_BLOCK_SIZE);
		// If successfully read, then copy
		memcpy(&client_auth.tempkey[0], &client_auth.dev_serial, ATCA_SERIAL_NUM_SIZE);
		
		disp_size = sizeof(disp_str);
		atcab_bin2hex( client_auth.tempkey,sizeof(client_auth.tempkey), disp_str, &disp_size);
		printf("HOST:Padded Serial Number:\n\r\n%s\r\n", disp_str);
		printf("\r\n");
		
		printf("HOST:Performing Pass Though Nonce Command\r\n");
		return_code = atcab_nonce(client_auth.tempkey);
		if (return_code != ATCA_SUCCESS)
		{
			printf("Nonce Command failed\r\n");
			break;
		}else
		{
			printf("\nTempKey SourceFlag Set\r\n");
			printf("\r\n");
		}
		
		printf("HOST:Performing GenDig Command, this sets TempKey with the root key in slot 0\r\n");
		return_code = atcab_gendig(DATA_ZONE, HOST_ROOT_KEY_SLOT_NO_CONSUMTION_COUNTING, client_auth.gen_dig_other_data, sizeof(client_auth.gen_dig_other_data));
		if (return_code != ATCA_SUCCESS)
		{
			printf("GenDig Command failed\r\n");
			break;
		}else
		{
			printf("GenDig Command executed\r\n");
			printf("\r\n");
		}
		
		uint8_t client_mode_for_mac = CLIENT_MODE_FOR_CAL_MAC;
		uint16_t client_slot_id_for_mac = (uint16_t)CLIENT_DERIVE_KEY_SLOT_NO_CONSUMTION_COUNTING;
		/*Formatting CHECKMAC other data with Opcode and CLIENT serial Number as described in data sheet*/

		memcpy(&client_auth.checkmac_other_data[1], &client_mode_for_mac, 1);				//Client Mode used for MAC
		memcpy(&client_auth.checkmac_other_data[2], &client_slot_id_for_mac, 2);			//Client Slot ID used for MAC
		memcpy(&client_auth.checkmac_other_data[7], &client_auth.dev_serial[4], 4);			//Client Serial number (4:7)
		memcpy(&client_auth.checkmac_other_data[11], &client_auth.dev_serial[2], 2);		//Client Serial number (2:3)
		
		printf("HOST: Performing CheckMAC using Random Challenge and Derive Key computed internally by HOST\r\n");
		return_code = atcab_checkmac( HOST_CHECK_MACK_MODE, HOST_DIVERSIFIED_KEY_SLOT_NO_CONSUMTION_COUNTING, client_auth.host_random, client_auth.sha_256_MAC, client_auth.checkmac_other_data);
		if (return_code != ATCA_SUCCESS)
		{
			printf("CLIENT IS NOT AUTHENTIC\r\n");
			break;
		}else
		{
			printf("\r\n");
			delay_ms(100);
			printf("CLIENT IS AUTHENTIC\r\n");
			printf("\r\n");
		}
		/*Calling NONCE Mode 3 "Pass Through Nonce Set value in Temp Key*/
		asm("nop");
	}while(0);
}

void authenticate_client_consumtion_counting(void)
{
	char disp_str[1500];
	int disp_size = sizeof(disp_str);
	uint8_t return_code = ATCA_SUCCESS;
	uint8_t config_zone_block = 1;
	uint8_t config_zone_offset = 5;
	uint8_t config_index = 0;
	
	/*HOST AUTHENTICATES A CLIENT DEVERSIFIED KEY USING ROOT KEY*/
	do{
		/*SET HOST SPECIFIC DELAY SINCE WE CHANGED I2C ADDRESS */
		cfg_sha204a_i2c_default.atcai2c.slave_address = DERIVED_KEY_HOST_I2C_ADDR;
		return_code = atcab_init( &cfg_sha204a_i2c_default );
		if (return_code != ATCA_SUCCESS)
		{
			printf("Not Communicating check I2C address\r\n");
			break;
		}else
		{
			printf("HOST \r\n");
			printf("Set HOST I2C address\r\n");
		}
		
		/*HOST GET RANDOM NUMBER*/
		return_code = atcab_random(client_auth_consumption_count.host_random);
		if (return_code != ATCA_SUCCESS)
		{
			printf("Random Number Generation failed\r\n");
			break;
		}else
		{
			disp_size = sizeof(disp_str);
			atcab_bin2hex( client_auth_consumption_count.host_random,sizeof(client_auth_consumption_count.host_random), disp_str, &disp_size);
			printf("HOST: Sending Random Challenge to Client:\n\r\n%s\r\n", disp_str);
			printf("\r\n");
		}
		
		/*SET HOST SPECIFIC DELAY SINCE WE CHANGED I2C ADDRESS */
		cfg_sha204a_i2c_default.atcai2c.slave_address = DERIVED_KEY_CLIENT_I2C_ADDR;
		return_code = atcab_init( &cfg_sha204a_i2c_default );
		if (return_code != ATCA_SUCCESS)
		{
			printf("Not Communicating check I2C address\r\n");
			break;
		}else
		{
			printf("CLIENT\r\n");
			printf("Set CLIENT I2C address\r\n");
			printf("\r\n");
		}
		
		
		
		config_index = 0;
		config_zone_offset = 0;
		config_zone_block = 2;
		printf("CLIENT: Reading UseFlag counter\r\n");
		printf("CLIENT: This is the Secondary Counter counter. Top count is 8\r\n");
		
		return_code = atcab_read_zone(ATCA_ZONE_CONFIG, 0, config_zone_block, config_zone_offset, client_auth_consumption_count.used_flag, ATCA_WORD_SIZE);
		if (return_code	!= ATCA_SUCCESS)
		{
			printf("Reading UseFlag counter failed\r\n");
			break;
		}
		else
		{
			printf("The secondary counter value is: %#01x\r\n",client_auth_consumption_count.used_flag[2]);
			printf("\r\n");
		}
		
		config_index = 0;
		config_zone_offset = 1;
		config_zone_block = 2;
		return_code = atcab_read_zone(ATCA_ZONE_CONFIG, 0, config_zone_block, config_zone_offset, &client_auth_consumption_count.last_key_used[config_index], ATCA_WORD_SIZE);
		if (return_code	!= ATCA_SUCCESS) break;
		config_zone_offset = 2;
		config_index += ATCA_WORD_SIZE;
		return_code = atcab_read_zone(ATCA_ZONE_CONFIG, 0, config_zone_block, config_zone_offset, &client_auth_consumption_count.last_key_used[config_index], ATCA_WORD_SIZE);
		if (return_code	!= ATCA_SUCCESS) break;
		config_zone_offset = 3;
		config_index += ATCA_WORD_SIZE;
		return_code = atcab_read_zone(ATCA_ZONE_CONFIG, 0, config_zone_block, config_zone_offset, &client_auth_consumption_count.last_key_used[config_index], ATCA_WORD_SIZE);
		if (return_code	!= ATCA_SUCCESS) break;
		config_zone_offset = 4;
		config_index += ATCA_WORD_SIZE;
		return_code = atcab_read_zone(ATCA_ZONE_CONFIG, 0, config_zone_block, config_zone_offset, &client_auth_consumption_count.last_key_used[config_index], ATCA_WORD_SIZE);
		if (return_code	!= ATCA_SUCCESS) break;
		config_zone_offset = 5;
		
		disp_size = sizeof(disp_str);
		atcab_bin2hex( client_auth_consumption_count.last_key_used,sizeof(client_auth_consumption_count.last_key_used), disp_str, &disp_size);
		printf("CLIENT: Reading Last Key Used, This is the main counter. Top count is 128\r\n");
		printf("CLIENT: This chaining technique will allow the counter to reach 128x8. Top is 1024\r\n");
		printf("%s\r\n", disp_str);
		printf("\r\n");
		
		/*CHECING COUNT FLAG, IF ITS ZERO, WE NEED TO ROLL*/
		if (client_auth_consumption_count.used_flag[2] == 0x00)
		{
			printf("Use Flag 1 = 0, performing DeriveKey cmd to roll\r\n");
			printf("This process will reset the secondary counter to a value of 8 (0xFF)\r\n");
			printf("It will also decrement the main counter by 1\r\n");
			// Set the pad bytes
			memset(&client_auth_consumption_count.tempkey[0], 0x77, ATCA_BLOCK_SIZE);
			// If successfully read, then copy
			memcpy(&client_auth_consumption_count.tempkey[0], &client_auth_consumption_count.dev_serial, ATCA_SERIAL_NUM_SIZE);

			//Performing Nonce command
			return_code = atcab_nonce(client_auth_consumption_count.tempkey);
			if (return_code != ATCA_SUCCESS)
			{
				printf("Nonce Command failed\r\n");
				break;
			}else
			{
				printf("TempKey SourceFlag Set\r\n");
				printf("\r\n");
			}
			
			//Executing DeriveKey Command to Roll Counter back to 0xFF
			return_code = atcab_derive_key(CLIENT_DERIVE_KEY_SLOT_CONSUMTION_COUNTING, false, NULL);
			asm("nop");
		}
		
		
		/*CLIENT GENERATE MAC (SHA 256 HASH) ON CLIENT USING DERIVED KEY IN SLOT 1 AND CHALANGE (RANDOM NUMBER)*/
		/*CLIENT CALCULATE MAC FROM DERIVED KEY IN SLOT 0x07 AND RANDOM CHALLANEGE FROM HOST*/
		return_code = atcab_mac( CLIENT_MODE_FOR_CAL_MAC, CLIENT_DERIVE_KEY_SLOT_CONSUMTION_COUNTING, client_auth_consumption_count.host_random, client_auth_consumption_count.sha_256_MAC );
		if (return_code	!= ATCA_SUCCESS)
		{
			printf("MAC failed\r\n");
		}
		else
		{
			disp_size = sizeof(disp_str);
			atcab_bin2hex( client_auth_consumption_count.sha_256_MAC,sizeof(client_auth_consumption_count.sha_256_MAC), disp_str, &disp_size);
			printf("CLIENT: Obtaining MAC for the consumption counting Diversified Key in Slot 7:\n\r\n%s\r\n", disp_str);
			printf("\r\n");
		}

		///*CLIENT Read Serial Number*/
		return_code = atcab_read_serial_number(client_auth_consumption_count.dev_serial);
		if (return_code != ATCA_SUCCESS)
		{
			printf("Read Serial Number failed\r\n");
			break;
		}else
		{
			disp_size = sizeof(disp_str);
			atcab_bin2hex( client_auth_consumption_count.dev_serial,sizeof(client_auth_consumption_count.dev_serial), disp_str, &disp_size);
			printf("CLIENT: Reading Client Serial Number:\n\r\n%s\r\n", disp_str);
			printf("Sending to HOST");
			printf("\r\n");
		}
		
		
		///*Set HOST I2C address*/
		cfg_sha204a_i2c_default.atcai2c.slave_address = DERIVED_KEY_HOST_I2C_ADDR;
		return_code = atcab_init( &cfg_sha204a_i2c_default );
		if (return_code != ATCA_SUCCESS)
		{
			printf("Not Communicating check I2C address\r\n");
			break;
		}else
		{
			printf("HOST \r\n");
			printf("Set HOST I2C address\r\n");
			printf("\r\n");
		}
		
		///*HOST PAD SERIAL NUMBER-> SERIAL + PAD OF 7's TO FORM A 32BYTE TEMP KEY*/
		// Set the pad bytes
		memset(&client_auth_consumption_count.tempkey[0], 0x77, ATCA_BLOCK_SIZE);
		// If successfully read, then copy
		memcpy(&client_auth_consumption_count.tempkey[0], &client_auth_consumption_count.dev_serial, ATCA_SERIAL_NUM_SIZE);
		
		disp_size = sizeof(disp_str);
		atcab_bin2hex( client_auth_consumption_count.tempkey,sizeof(client_auth_consumption_count.tempkey), disp_str, &disp_size);
		printf("HOST: Padding Serial Number from CLIENT with 0x77:\n\r\n%s\r\n", disp_str);
		printf("\r\n");

		printf("HOST:Performing Pass Though Nonce Command, This will place the padded Client serial number in TempKey\r\n");
		return_code = atcab_nonce(client_auth_consumption_count.tempkey);
		if (return_code != ATCA_SUCCESS)
		{
			printf("Nonce Command failed\r\n");
			break;
		}else
		{
			printf("TempKey SourceFlag Set\r\n");
			printf("\r\n");
		}
		
		printf("HOST:Performing GenDig Command to Initialize\rInternal TempKey slot with the Diversified Key\r\n");
		return_code = atcab_gendig(DATA_ZONE, HOST_ROOT_KEY_SLOT_CONSUMTION_COUNTING, client_auth_consumption_count.gen_dig_other_data, sizeof(client_auth_consumption_count.gen_dig_other_data));
		if (return_code != ATCA_SUCCESS)
		{
			printf("GenDig Command failed\r\n");
			break;
		}else
		{
			printf("GenDig Command executed\r\n");
			printf("\r\n");
		}
		
		uint8_t client_mode_for_mac = CLIENT_MODE_FOR_CAL_MAC;
		uint16_t client_slot_id_for_mac = (uint16_t)CLIENT_DERIVE_KEY_SLOT_CONSUMTION_COUNTING;
		/*Formatting CHECKMAC other data with Opcode and CLIENT serial Number as described in data sheet*/

		memcpy(&client_auth_consumption_count.checkmac_other_data[1], &client_mode_for_mac, 1);				//Client Mode used for MAC
		memcpy(&client_auth_consumption_count.checkmac_other_data[2], &client_slot_id_for_mac, 2);			//Client Slot ID used for MAC
		memcpy(&client_auth_consumption_count.checkmac_other_data[7], &client_auth_consumption_count.dev_serial[4], 4);			//Client Serial number (4:7)
		memcpy(&client_auth_consumption_count.checkmac_other_data[11], &client_auth_consumption_count.dev_serial[2], 2);		//Client Serial number (2:3)

		printf("HOST: Performing CheckMAC using Random Challenge and Derive Key computed internally by HOST\r\n");
		return_code = atcab_checkmac( HOST_CHECK_MACK_MODE, CLIENT_DERIVE_KEY_SLOT_CONSUMTION_COUNTING, 
		client_auth_consumption_count.host_random, 
		client_auth_consumption_count.sha_256_MAC, 
		client_auth_consumption_count.checkmac_other_data);
		if (return_code != ATCA_SUCCESS)
		{
			printf("CLIENT IS NOT AUTHENTIC\r\n");
			break;
		}else
		{
			printf("\r\n");
			delay_ms(100);
			printf("CLIENT IS AUTHENTIC\r\n");
		}
		asm("nop");
	}while(0);
}

