#ifndef INCLUDE_MOD_ENUMS_H_
#define INCLUDE_MOD_ENUMS_H_

#include <user_interface.h>

void lookup_station_status(char* buffer, uint8 value);
void lookup_cipher(char* buffer, CIPHER_TYPE value);
void lookup_espconn_error(char* buffer, sint8 value);

#endif /* INCLUDE_MOD_ENUMS_H_ */
