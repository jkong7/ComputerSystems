// Application to test unpack utilities
// PackLab - CS213 - Northwestern University

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "unpack-utilities.h"

// 1. PARSE_HEADER 

int test_parse_header(void) {
    // Create input data that represents a valid header
    uint8_t input_data[] = {
        0x02, 0x13,       // Magic number (0x0213)
        0x03,             // Version (0x03)
        0xE4,             // Flags: compressed, encrypted, checksummed
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, // Original size (32 bytes)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, // Data size (16 bytes)
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, // Dictionary data (16 bytes)
        0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, // Additional dictionary bytes
        0x12, 0x34        // Checksum (0x1234)
    };


    size_t input_len = sizeof(input_data);

    // Create an expected config object for comparison
    packlab_config_t expected_config = {
        .is_valid = true,
        .header_len = 38,
        .is_compressed = true,
        .is_encrypted = true,
        .is_checksummed = true,
        .checksum_value = 0x1234,
        .should_continue = false,
        .should_float = false,
        .should_float3 = false,
        .orig_data_size = 32,
        .data_size = 16,
    };
    memcpy(expected_config.dictionary_data, &input_data[20], 16);

    // Create a config object to hold the parsed results
    packlab_config_t parsed_config;

    // Run the function being tested
    parse_header(input_data, input_len, &parsed_config);

    // Check the validity
    if (!parsed_config.is_valid) {
        printf("ERROR: Parsed header is invalid when it should be valid.\n");
        return 1;
    }

    // Compare the parsed config to the expected config
    if (memcmp(&parsed_config, &expected_config, sizeof(packlab_config_t)) != 0) {
        printf("ERROR: Parsed config does not match expected config.\n");
        return 1;
    }

    printf("ONE: test_parse_header passed.\n");
    return 0;
}


// 2. CALCULATE_CHECKSUM 

int test_calculate_checksum(void) {
  // Create input data to test with
  // If you wanted to test a header, these would be bytes of the header with
  //    meaningful bytes in appropriate places
  // If you want to test one of the other functions, they can be any bytes
  uint8_t input_data[] = {0x01, 0x03, 0x04, };

  // Create an "expected" result to compare against
  // If you're testing header parsing, you will likely need one of these for
  //    each config field. If you're testing decryption or decompression, this
  //    should be an array of expected output_data bytes
  uint16_t expected_checksum_value = 0x0008;

  // Actually run your code
  // Note that `sizeof(input_data)` actually returns the number of bytes for the
  //    array because it's a local variable (`sizeof()` generally doesn't return
  //    buffer lengths in C for arrays that are passed in as arguments)
  uint16_t calculated_checksum_value = calculate_checksum(input_data, sizeof(input_data));

  // Compare the results
  // This might need to be multiple comparisons or even a loop that compares many bytes
  // `memcmp()` in the C standard libary might be a useful function here!
  // Note, you don't _need_ the CHECK() functions like we used in CS211, you
  //    can just return 1 then print that there was an error
  if (calculated_checksum_value != expected_checksum_value) {
    // Test failed! Return 1 to signify failure
    return 1;
  }

  printf("TWO: test_calculate_checksum passed.\n");
  return 0;
}

// 3. LSFR_STEP
int test_lfsr_step(void) {
  // A properly created LFSR should do two things
  //  1. It should generate specific new state based on a known initial state
  //  2. It should iterate through all 2^16 integers, once each (except 0)

  // Create an array to track if the LFSR hit each integer (except 0)
  // 2^16 (65536) possibilities
  bool* lfsr_states = malloc_and_check(65536);
  memset(lfsr_states, 0, 65536);

  // Initial 16 LFSR states
  uint16_t correct_lfsr_states[16] = {
    0x1337, 0x099B, 0x84CD, 0x4266,
    0x2133, 0x1099, 0x884C, 0xC426,
    0x6213, 0xB109, 0x5884, 0x2C42,
    0x1621, 0x0B10, 0x8588, 0x42C4
  };

  // Step the LFSR until a state repeats
  bool repeat        = false;
  size_t steps       = 0;
  uint16_t new_state = 0x1337; // known initial state
  while (!repeat) {

    // Iterate LFSR
    steps++;
    new_state = lfsr_step(new_state);

    // Check if this state has already been reached
    repeat = lfsr_states[new_state];
    lfsr_states[new_state] = true;

    // Check first 16 LFSR steps
    if (steps < 16) {
      if (new_state != correct_lfsr_states[steps]) {
        printf("ERROR: at step %lu, expected state 0x%04X but received state 0x%04X\n",
            steps, correct_lfsr_states[steps], new_state);
        free(lfsr_states);
        return 1;
      }
    }
  }

  // Check that all integers were hit. Should take 2^16 (65536) steps (2^16-1 integers, plus a repeat)
  if (steps != 65536) {
    printf("ERROR: expected %d iterations before a repeat, but ended after %lu steps\n", 65536, steps);
    free(lfsr_states);
    return 1;
  }

  // Cleanup
  free(lfsr_states);

  printf("THREE: test_lsfr_step passed.\n");
  return 0;
}

// 4. DECRYPT_DATA 

int test_decrypt_data(void) {
    uint8_t input_data[] = {0x60, 0x5A, 0xFF, 0xB7};
    size_t input_len = sizeof(input_data);

    uint8_t expected_output[] = {0xFB, 0x53, 0x32, 0x33};
    size_t expected_output_len = sizeof(expected_output);

    uint8_t output_data[16] = {0}; 
    size_t output_len = sizeof(output_data);

    uint16_t encryption_key = 0x1337; 

    decrypt_data(input_data, input_len, output_data, output_len, encryption_key);

    if (expected_output_len != input_len) {
        printf("ERROR: Decrypted data length mismatch."); 
        return 1;
    }

    if (memcmp(output_data, expected_output, expected_output_len) != 0) {
        printf("ERROR: Decrypted data mismatch.\n");
        return 1;
    }

    printf("FOUR: test_decrypt_data passed.\n");
    return 0;
}



// 5. DECOMPRESS_DATA: PASS
int test_decompress_data(void) { 

    // TEST ONE

    uint8_t input_data[] = {
        0x01,        
        0x07, 0x12,  
        0x07, 0x00,  
        0x02         
    };

    size_t input_len = sizeof(input_data);

    uint8_t dictionary_data[16] = {
        0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0x3E, 0x3F
    };

    uint8_t output_data[16] = {0}; 

    size_t output_len = sizeof(output_data);
    

    uint8_t expected_output[] = {
        0x01,       
        0x32,      
        0x07,        
        0x02        
    };

    size_t expected_output_len = sizeof(expected_output);

    size_t decompressed_len = decompress_data(
        input_data, input_len,
        output_data, output_len,
        dictionary_data
    );

    if (decompressed_len != expected_output_len) {
        printf("ERROR 1: Decompressed length mismatch. \n"); 
        return 1;
    }

    if (memcmp(output_data, expected_output, expected_output_len) != 0) {
        printf("ERROR 1: Decompressed data mismatch.\n");
        return 1;
    }

    // TEST TWO

    uint8_t input_data_2[] = {
        0x07, 0x00,  
        0x07, 0x34,  
        0x03,        
        0x07         
    };

    size_t input_len_2 = sizeof(input_data_2);

    uint8_t dictionary_data_2[16] = {
        0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0x3E, 0x3F
    };

    uint8_t output_data_2[16] = {0}; 

    size_t output_len_2 = sizeof(output_data_2);

    uint8_t expected_output_2[] = {
        0x07,       
        0x34, 0x34, 0x34, 
        0x03,       
        0x07        
    };

    size_t expected_output_len_2 = sizeof(expected_output_2);

    size_t decompressed_len_2 = decompress_data(
        input_data_2, input_len_2,
        output_data_2, output_len_2,
        dictionary_data_2
    );

    if (decompressed_len_2 != expected_output_len_2) {
        printf("ERROR 2: Decompressed length mismatch.\n"); 
        return 1;
    }

    if (memcmp(output_data_2, expected_output_2, expected_output_len_2) != 0) {
        printf("ERROR 2: Decompressed data mismatch.\n");
        return 1;
    }

    // TEST THREE
    uint8_t input_data_3[] = {
        0x01,        
        0x07, 0x12,  
        0x07, 0x34,  
        0x02,        
        0x07, 0x00,  
        0x07, 0x21,  
        0x07, 0x54,  
        0x07, 0x00,  
        0x03         
    };

    size_t input_len_3 = sizeof(input_data_3);

    uint8_t dictionary_data_3[16] = {
        0x30, 0x31, 0x32, 0x33,
        0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3A, 0x3B,
        0x3C, 0x3D, 0x3E, 0x3F
    };

    uint8_t output_data_3[64] = {0}; 

    size_t output_len_3 = sizeof(output_data_3);

    uint8_t expected_output_3[] = {
        0x01,       
        0x32,       
        0x34, 0x34, 0x34, 
        0x02,       
        0x07,       
        0x31, 0x31,        
        0x34, 0x34, 0x34, 0x34, 0x34, 
        0x07,       
        0x03        
    };

    size_t expected_output_len_3 = sizeof(expected_output_3);

    size_t decompressed_len_3 = decompress_data(
        input_data_3, input_len_3,
        output_data_3, output_len_3,
        dictionary_data_3
    );

    if (decompressed_len_3 != expected_output_len_3) {
        printf("ERROR 3: Decompressed length mismatch.\n"); 
        return 1;
    }

    if (memcmp(output_data_3, expected_output_3, expected_output_len_3) != 0) {
        printf("ERROR 3: Decompressed data mismatch.\n");
        return 1;
    }

    printf("FIVE: test_decompress_data passed.\n");
    return 0; 
}

// 6. JOIN_FLOAT_ARRAY 
int test_join_float_array(void) {
    uint8_t input_signfrac[] = {0x00, 0x00, 0x96};
    uint8_t input_exp[] = {0x87};
    uint8_t expected_output[] = {0x00, 0x00, 0x96, 0x43};
    uint8_t output_data[4] = {0}; // Initialize to 0 for clarity

    // Call the function being tested
    join_float_array(input_signfrac, sizeof(input_signfrac),
                     input_exp, sizeof(input_exp),
                     output_data, sizeof(output_data));

    // Print the output bytes for debugging
    printf("Output bytes: 0x%02X 0x%02X 0x%02X 0x%02X\n",
           output_data[0], output_data[1], output_data[2], output_data[3]);

    // Compare the actual output to the expected output
    if (memcmp(output_data, expected_output, sizeof(expected_output)) != 0) {
        printf("ERROR: test_join_float_array failed\n");
        return 1;
    }
    printf("SIX: test_join_float_array passed.\n");
    return 0; // Test passed
}



int main(void) {

  // 1. PARSE_HEADER
  //int result = test_parse_header();
  //if (result != 0) {
  //  printf("ERROR: parse_header failed\n");
  //  return 1;
  //}


  // 2. CALCULATE_CHECKSUM
  int result = test_calculate_checksum();
  if (result != 0) {
    printf("ERROR: calculate_checksum failed\n");
    return 1;
  }

  // 3. LSFR_STEP
  result = test_lfsr_step();
  if (result != 0) {
    printf("ERROR: test_lfsr_step failed\n");
    return 1;
  }

  // 4. DECRYPT_DATA 

  result = test_decrypt_data();
  if (result != 0) {
      printf("ERROR: test_decrypt_data failed\n");
      return 1;
  }

  // 5. DECOMPRESS_DATA 
  result = test_decompress_data();
  if (result != 0) {
      printf("ERROR: test_decompress_data failed\n");
      return 1;
  }

  // 6. JOIN_FLOAT_ARRAY
  result = test_join_float_array();
  if (result != 0) {
      printf("ERROR: test_join_float_array failed\n");
      return 1;
  }

  printf("All tests passed successfully!\n");
  return 0;
}

