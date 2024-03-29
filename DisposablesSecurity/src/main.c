/** \file Host driver for atca-ng test and development
*
* Copyright (C) 2012-2015 Atmel Corporation. All rights reserved.
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
*
*/


#include <asf.h>
#include "cbuf.h"
#include "usart.h"
#include "sio2host.h"
#include "conf_sio2host.h"
#include "stdio_serial.h"
#include "cmd-processor.h"
#include "cryptoauthlib.h"


int main(void)
{
  static uint8_t status;
  char disp_str[1700];
  int disp_size = sizeof(disp_str);
  
  system_init();
  
  delay_init();
  
  // Initialize interrupt vector table support.
  irq_initialize_vectors();
  
  // Enable interrupts
  cpu_irq_enable();
  
  sio2host_init();
  
  printf("\f");
  help();
  printf("$");
  
  while (true) {
    uint8_t ch = 0;
    int back = sio2host_rx(&ch, 1);
    if (back >= 1)
    {
      printf("%c",ch); // echo to output
      if ( ch == 0x0d || ch == 0x0a ) {
        processCmd();
        } else {
        CBUF_Push( cmdQ, ch );  // queue character into circular buffer
      }
    }
  }
}
