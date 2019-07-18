/** \file cmd_processor.c
* simple command processor for example console
*
* Copyright (c) 2015 Atmel Corporation. All rights reserved.
*
* \asf_license_start
*
* \page License
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions are met:
*
* 1. Redistributions of source code must retain the above copyright notice,
*    this list of conditions and the following disclaimer.
*
* 2. Redistributions in binary form must reproduce the above copyright notice,
*    this list of conditions and the following disclaimer in the documentation
*    and/or other materials provided with the distribution.
*
* 3. The name of Atmel may not be used to endorse or promote products derived
*    from this software without specific prior written permission.
*
* 4. This software may only be redistributed and used in connection with an
*    Atmel microcontroller product.
*
* THIS SOFTWARE IS PROVIDED BY ATMEL "AS IS" AND ANY EXPRESS OR IMPLIED
* WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
* MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT ARE
* EXPRESSLY AND SPECIFICALLY DISCLAIMED. IN NO EVENT SHALL ATMEL BE LIABLE FOR
* ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
* STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
* ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
* POSSIBILITY OF SUCH DAMAGE.
*
* \asf_license_stop
*/

#include <asf.h>
#include <string.h>
#include "cbuf.h"
#include "usart.h"
#include "sio2host.h"
#include "conf_sio2host.h"
#include "stdio_serial.h"
#include "cmd-processor.h"
#include "cryptoauthlib.h"
#include "provisioning.h"
#include "disposable_auth.h"


/** \defgroup console Console functionality for node-auth-basic example
*
* \brief The console simply buffers keyboard input from the serial port and
* store a command.  Once a newline is found, it calls the code to parse the command
* and execute it.
*
@{ */

	/** \brief help method prints out the console menu commands to the console
	\return ATCA_STATUS
	*/

	int help(void)
	{
		printf("DISPOSABLE AUTHENTICATION TRAINING:\r\n");
		printf("Usage:\r\n");
		printf("host_provision                    ---Command will provision Host\r\n");
		printf("client_provision                  ---Command will provision Client\r\n");
		printf("authenticate_client               ---Command will Initiate Client Authentication by Host\r\n");
		printf("authenticate_client_counters      ---Command will Initiate Client Authentication by Host with Monotonic Counter Enabled\r\n");
		printf("\r\n");
		return ATCA_SUCCESS;
	}

	uint8_t cmdbytes[128];


	/** \brief parseCmd takes a command string entered from the console and executes the command
	*  requested.
	*  \param[in] commands - a command string
	*/

	int parseCmd( char *commands )
	{
		if (!strcmp( commands, "help")) {
			printf("\r\n");
			help();
		}else
		if (!strcmp( commands, "host_provision")) {
			printf("\r\n");
			host_provision();
		} else
		if (!strcmp( commands, "client_provision")) {
			printf("\r\n");
			client_provision();
		}else
		if (!strcmp( commands, "authenticate_client")) {
			printf("\r\n");
			authenticate_client();
		}else
		if (!strcmp( commands, "authenticate_client_counters")) {
			printf("\r\n");
			authenticate_client_consumtion_counting();
		}else if ( strlen(commands) ) {
		printf("\r\nsyntax error in command: %s\r\n", commands);
		}
		return ATCA_SUCCESS;
	}

	/** \brief processCmd empties a circular buffer of stored command characters
	* int a command string, then makes the call to parse and execute the command
	*/
	int processCmd(void)
	{
		static char cmd[256];
		uint16_t i = 0;
		while( !CBUF_IsEmpty(cmdQ) && i < sizeof(cmd))
		cmd[i++] = CBUF_Pop( cmdQ );
		cmd[i] = '\0';
		//printf("\r\n%s\r\n", command );
		parseCmd(cmd);
		printf("$ ");
		
		return ATCA_SUCCESS;
	}


	/** @} */

