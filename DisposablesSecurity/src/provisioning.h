/*
 * host_provision.h
 *
 * Created: 3/28/2016 9:52:22 AM
 *  Author: oscar.sanchez
 */ 


#ifndef SHA204_PROVISION_H_
#define SHA204_PROVISION_H_

/*Structure used to generate the DeriveKey that will be stored in the Client device*/
struct client_derive_key_t {
	uint8_t root_key[32];
	uint8_t op_code[1];
	uint8_t mode[1];
	uint8_t param[2];
	uint8_t serial_8[1];
	uint8_t serial_0_1[2];
	uint8_t zeros[25];
	uint8_t temp_key[32];
};

int host_provision(void);
int host_write_data_zone(const uint8_t * data, uint16_t len);

int generate_derive_key(uint8_t * derive_key, uint8_t derive_slot, uint8_t * root_key);
int client_provision(void);
int client_write_data_zone(const uint8_t * data, uint16_t len);

#endif /* SHA204_PROVISION_H_ */