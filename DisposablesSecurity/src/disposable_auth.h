/*
 * disposable_auth.h
 *
 * Created: 7/13/16 5:48:43 PM
 *  Author: sanchezoscar
 */ 


#ifndef DISPOSABLE_AUTH_H_
#define DISPOSABLE_AUTH_H_

#define CLIENT_DERIVE_KEY_SLOT_NO_CONSUMTION_COUNTING	0x01
#define CLIENT_DERIVE_KEY_SLOT_CONSUMTION_COUNTING	0x07
#define CLIENT_MODE_FOR_CAL_MAC			0x40

#define DATA_ZONE					0x02
#define HOST_ROOT_KEY_SLOT_CONSUMTION_COUNTING		0x0F
#define HOST_ROOT_KEY_SLOT_NO_CONSUMTION_COUNTING	0x00

#define HOST_CHECK_MACK_MODE			0x06 	//Use TempKey and match TempKey source flag
#define HOST_DIVERSIFIED_KEY_SLOT_NO_CONSUMTION_COUNTING	0x01

#define MODE_FOR_DERIVE_KEY_CMD	0x04


/*************GLOBAL VARIABLES**************/
/*Used to Verify I2C address*/
extern uint8_t i2cHost;
extern uint8_t i2cClient;

/*************STRUCT************************/
/*Structure used during the authentication process*/
struct client_auth_t {
	uint8_t  host_random[32];
	uint8_t  sha_256_MAC[32];
	uint8_t	 gen_dig_other_data[4];
	uint8_t  checkmac_other_data[13];
	uint8_t  dev_serial[9];
	uint8_t	 tempkey[32];
	uint8_t	 used_flag[4];
	uint8_t	 last_key_used[16];
	bool	 dev_Key_match;
};

/*Structure used during the authentication process*/
struct encrypt_write_t {
	uint8_t rand_out[32];
	uint8_t NonceRand[55];
	uint8_t TempKeyWrite[96];
	uint8_t TempKey[32];
	uint8_t AuthMAC[96];
	uint8_t XOR_buff[32];
	uint8_t AuthMacOutPut[32];
};




extern void authenticate_client(void);
extern void authenticate_client_consumtion_counting(void);



#endif /* DISPOSABLE_AUTH_H_ */