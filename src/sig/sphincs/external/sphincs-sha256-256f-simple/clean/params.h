#ifndef SPX_PARAMS_H
#define SPX_PARAMS_H

/* Hash output length in bytes. */
#define SPX_N 32
/* Height of the hypertree. */
//#define SPX_FULL_HEIGHT 68
/* Number of subtree layer. */
//#define SPX_D 17
/* FORS tree dimensions. */
//#define SPX_FORS_HEIGHT 10
//#define SPX_FORS_TREES 30
/* Winternitz parameter, */
//#define SPX_WOTS_W 16

/* PANOS SPHINCS+ custom parameter testing
   using the testing and the parameter set flag
   These definitions are used in ifndefs in 
   sphincs-sha256-192f-simple and sphincs-sha256-256f-simple */
// Testing SPHINCS custom parameters
// TODO: Set or unset.
#define SPHINCS_CUSTOM_PARAM_TESTING
// Parameter sets. TODO: ONLY USE ONE. 
//#define H15_W16
//#define H15_W256
//#define H20_W16
//#define H20_W256
#define H35_W16
//#define H35_W256
#ifdef SPHINCS_CUSTOM_PARAM_TESTING 
  #if defined(H15_W16)
    #define SPX_FULL_HEIGHT 15
    #define SPX_D 3
    #define SPX_FORS_HEIGHT 16 
    #define SPX_FORS_TREES 19
    #define SPX_WOTS_W 16
  #elif defined(H15_W256)
    #define SPX_FULL_HEIGHT 15
    #define SPX_D 3
    #define SPX_FORS_HEIGHT 16 
    #define SPX_FORS_TREES 19
    #define SPX_WOTS_W 256
  #elif defined(H20_W16)
    #define SPX_FULL_HEIGHT 20
    #define SPX_D 2
    #define SPX_FORS_HEIGHT 16 
    #define SPX_FORS_TREES 19
    #define SPX_WOTS_W 16
  #elif defined(H20_W256)
    #define SPX_FULL_HEIGHT 20
    #define SPX_D 2
    #define SPX_FORS_HEIGHT 16 
    #define SPX_FORS_TREES 19
    #define SPX_WOTS_W 256
  #elif defined(H35_W16)
    #define SPX_FULL_HEIGHT 35
    #define SPX_D 5
    #define SPX_FORS_HEIGHT 15 
    #define SPX_FORS_TREES 21
    #define SPX_WOTS_W 16
  #elif defined(H35_W256)
    #define SPX_FULL_HEIGHT 35
    #define SPX_D 5
    #define SPX_FORS_HEIGHT 15 
    #define SPX_FORS_TREES 21
    #define SPX_WOTS_W 256
  #else // default sphincs-sha256-256f-simple parameters
    #define SPX_FULL_HEIGHT 68
    #define SPX_D 17
    #define SPX_FORS_HEIGHT 10
    #define SPX_FORS_TREES 30
    #define SPX_WOTS_W 16
  #endif
#else // default sphincs-sha256-256f-simple parameters
  #define SPX_FULL_HEIGHT 68
  #define SPX_D 17
  #define SPX_FORS_HEIGHT 10
  #define SPX_FORS_TREES 30
  #define SPX_WOTS_W 16
#endif // SPHINCS_CUSTOM_PARAM_TESTING 

/* The hash function is defined by linking a different hash.c file, as opposed
   to setting a #define constant. */

/* For clarity */
#define SPX_ADDR_BYTES 32

/* WOTS parameters. */
#define SPX_WOTS_LOGW 4

#define SPX_WOTS_LEN1 (8 * SPX_N / SPX_WOTS_LOGW)

/* SPX_WOTS_LEN2 is floor(log(len_1 * (w - 1)) / log(w)) + 1; we precompute */
#define SPX_WOTS_LEN2 3

#define SPX_WOTS_LEN (SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES (SPX_WOTS_LEN * SPX_N)
#define SPX_WOTS_PK_BYTES SPX_WOTS_BYTES

/* Subtree size. */
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)

/* FORS parameters. */
#define SPX_FORS_MSG_BYTES ((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8)
#define SPX_FORS_BYTES ((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES SPX_N

/* Resulting SPX sizes. */
#define SPX_BYTES (SPX_N + SPX_FORS_BYTES + SPX_D * SPX_WOTS_BYTES +\
                   SPX_FULL_HEIGHT * SPX_N)
#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)

/* Optionally, signing can be made non-deterministic using optrand.
   This can help counter side-channel attacks that would benefit from
   getting a large number of traces when the signer uses the same nodes. */
#define SPX_OPTRAND_BYTES 32

#endif
