// Utilities for unpacking files
// PackLab - CS213 - Northwestern University

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unpack-utilities.h"


// --- public functions ---

void error_and_exit(const char* message) {
  fprintf(stderr, "%s", message);
  exit(1);
}

void* malloc_and_check(size_t size) {
  void* pointer = malloc(size);
  if (pointer == NULL) {
    error_and_exit("ERROR: malloc failed\n");
  }
  return pointer;
}

void parse_header(uint8_t* input_data, size_t input_len, packlab_config_t* config) {

  config -> is_valid = true; 
  config -> header_len = 20; 

  if (input_len < 20) {
    config->is_valid = false;
    return;
  }


  uint16_t magic_number = (input_data[0] << 8) | input_data[1]; 
  uint8_t version = input_data[2]; 
  if (magic_number!=0x0213 || version!=0x03) {
    config->is_valid = false; 
    return; 
  } 


  uint8_t flags = input_data[3]; 
  config->should_float3 = (flags >> 2) & 1;
  config->should_float = (flags >> 3) & 1;
  config->should_continue = (flags >> 4) & 1;
  config->is_checksummed = (flags >> 5) & 1;
  config->is_encrypted = (flags >> 6) & 1;
  config->is_compressed = (flags >> 7) & 1;

  if (config -> is_compressed) {
    config -> header_len += 16; 
  }

  if (config -> is_checksummed) {
    config -> header_len +=2; 
  }


  if (input_len < config->header_len) {
    config->is_valid = false;
    return;
  }

  if (config->is_compressed) {
    memcpy(config->dictionary_data, &input_data[20], 16);
  }

  if (config->is_checksummed) {
    size_t checksum_offset =config->is_compressed ? 36 : 20;
    config->checksum_value = (input_data[checksum_offset] << 8) | input_data[checksum_offset + 1];
  }


  config->orig_data_size = ((uint64_t)input_data[4])       |
                           ((uint64_t)input_data[5] << 8)  |
                           ((uint64_t)input_data[6] << 16) |
                           ((uint64_t)input_data[7] << 24) |
                           ((uint64_t)input_data[8] << 32) |
                           ((uint64_t)input_data[9] << 40) |
                           ((uint64_t)input_data[10] << 48) |
                           ((uint64_t)input_data[11] << 56);


  config->data_size = ((uint64_t)input_data[12])       |
                      ((uint64_t)input_data[13] << 8)  |
                      ((uint64_t)input_data[14] << 16) |
                      ((uint64_t)input_data[15] << 24) |
                      ((uint64_t)input_data[16] << 32) |
                      ((uint64_t)input_data[17] << 40) |
                      ((uint64_t)input_data[18] << 48) |
                      ((uint64_t)input_data[19] << 56);

  if (config->orig_data_size ==0 && config->data_size == 0) {
    config->is_valid = true;  
    return;
  }
}

uint16_t calculate_checksum(uint8_t* input_data, size_t input_len) {
 
  uint16_t checksum_value = 0; 
  for (size_t i=0; i<input_len; i++) {
    checksum_value += input_data[i]; 
  }
  return checksum_value; 
}

uint16_t lfsr_step(uint16_t oldstate) {

  uint16_t xor_result = (oldstate & 1) ^ ((oldstate >> 6) & 1) ^ ((oldstate >> 9) & 1) ^ ((oldstate >> 13) & 1); 

  oldstate >>= 1; 

  oldstate = oldstate | (xor_result << 15); 

  return oldstate;  
}



/* End of mandatory implementation. */

/* Extra credit */
void join_float_array_three_stream(uint8_t* input_frac,
                                   size_t   input_len_bytes_frac,
                                   uint8_t* input_exp,
                                   size_t   input_len_bytes_exp,
                                   uint8_t* input_sign,
                                   size_t   input_len_bytes_sign,
                                   uint8_t* output_data,
                                   size_t   output_len_bytes) {

  // TODO
  // Combine three streams of bytes, one with frac data, one with exp data,
  // and one with sign data, into one output stream of floating point data
  // Output bytes are in little-endian order

}

