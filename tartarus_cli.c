#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define BLOCK_WORDS 256
typedef struct { uint32_t v[BLOCK_WORDS]; } Block;


/* ========================================================================= *
 * 1. THE MATHEMATICAL ENGINE (Tartarus)                                     *
 * ========================================================================= */

static inline void chacha_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b; *d ^= *a; *d = (uint32_t)((*d << 16) | (*d >> 16));
    *c += *d; *b ^= *c; *b = (uint32_t)((*b << 12) | (*b >> 20));
    *a += *b; *d ^= *a; *d = (uint32_t)((*d << 8)  | (*d >> 24));
    *c += *d; *b ^= *c; *b = (uint32_t)((*b << 7)  | (*b >> 25));
}

static inline void chacha_double_round(uint32_t s[16]) {
    chacha_quarter_round(&s[0], &s[4], &s[8],  &s[12]);
    chacha_quarter_round(&s[1], &s[5], &s[9],  &s[13]);
    chacha_quarter_round(&s[2], &s[6], &s[10], &s[14]);
    chacha_quarter_round(&s[3], &s[7], &s[11], &s[15]);
    chacha_quarter_round(&s[0], &s[5], &s[10], &s[15]);
    chacha_quarter_round(&s[1], &s[6], &s[11], &s[12]);
    chacha_quarter_round(&s[2], &s[7], &s[8],  &s[13]);
    chacha_quarter_round(&s[3], &s[4], &s[9],  &s[14]);
}

static inline void mix_block(Block *blk) {
    for (int i = 0; i < BLOCK_WORDS; i += 16)
        for (int r = 0; r < 10; r++) chacha_double_round(&blk->v[i]);
    for (int i = 0; i < 16; i++) {
        uint32_t row[16];
        for (int j = 0; j < 16; j++) row[j] = blk->v[j * 16 + i];
        for (int r = 0; r < 10; r++) chacha_double_round(row);
        for (int j = 0; j < 16; j++) blk->v[j * 16 + i] = row[j];
    }
}

static inline void xor_blocks(Block *dst, const Block *src1, const Block *src2) {
    for (int i = 0; i < BLOCK_WORDS; i++) dst->v[i] = src1->v[i] ^ src2->v[i];
}

static inline void init_pool_block(Block *dst, const Block *state, uint32_t index) {
    *dst = *state;
    dst->v[0] ^= index;
    dst->v[1] ^= ~index;
    dst->v[2] ^= (index << 16) | (index >> 16);
    dst->v[3] ^= index * 0x9E3779B9; 
    mix_block(dst);
}

int crypto_memcmp(const char *a, const char *b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= ((uint8_t)a[i] ^ (uint8_t)b[i]);
    return diff == 0;
}

int tartarus_verify(const char *stored_hash, const char *computed_hash) {
    if (strlen(stored_hash) != 128 || strlen(computed_hash) != 128) return 0;
    return crypto_memcmp(stored_hash, computed_hash, 128);
}

int tartarus(const uint8_t *data, size_t data_len, const uint8_t *salt, size_t salt_len, const uint8_t *pepper, size_t pepper_len, uint32_t memory_mb, uint32_t iterations, char *out_hex) {
    uint8_t digest[64]; unsigned int digest_len = 0;
    HMAC_CTX *ctx = HMAC_CTX_new();
    if (ctx == NULL) return -1;

    uint8_t len_prefix[8];
    len_prefix[0] = (salt_len >> 24) & 0xFF; len_prefix[1] = (salt_len >> 16) & 0xFF;
    len_prefix[2] = (salt_len >> 8) & 0xFF;  len_prefix[3] = salt_len & 0xFF;
    len_prefix[4] = (data_len >> 24) & 0xFF; len_prefix[5] = (data_len >> 16) & 0xFF;
    len_prefix[6] = (data_len >> 8) & 0xFF;  len_prefix[7] = data_len & 0xFF;

    HMAC_Init_ex(ctx, pepper, pepper_len, EVP_sha512(), NULL);
    HMAC_Update(ctx, len_prefix, 8);
    HMAC_Update(ctx, salt, salt_len);
    HMAC_Update(ctx, data, data_len);
    if (!HMAC_Final(ctx, digest, &digest_len) || digest_len != 64) { HMAC_CTX_free(ctx); return -1; }
    HMAC_CTX_free(ctx);

    Block state_block; memset(&state_block, 0, sizeof(Block));
    memcpy(state_block.v, digest, 64); mix_block(&state_block);

    uint32_t block_count = (memory_mb * 1024 * 1024) / sizeof(Block);
    if (block_count < 4) block_count = 4;
    Block *memory_pool = (Block *)malloc(block_count * sizeof(Block));
    if (memory_pool == NULL) { memset(digest, 0, 64); return -1; }

    init_pool_block(&memory_pool[0], &state_block, 1);
    init_pool_block(&memory_pool[1], &state_block, 2);

    for (uint32_t i = 2; i < block_count; i++) {
        uint32_t pr_a = memory_pool[i - 1].v[0] ^ state_block.v[i % 16];
        uint32_t pr_b = memory_pool[i - 1].v[1] ^ state_block.v[(i + 1) % 16];
        uint32_t pseudo_rand = pr_a ^ ((pr_b << 16) | (pr_b >> 16));
        uint32_t ref_index = (uint32_t)(((uint64_t)pseudo_rand * i) >> 32);
        
        xor_blocks(&memory_pool[i], &memory_pool[i - 1], &memory_pool[ref_index]);
        mix_block(&memory_pool[i]);
    }

    uint32_t accumulator = memory_pool[block_count - 1].v[0];
    Block tmp;
    for (uint32_t iter = 0; iter < iterations; iter++) {
        state_block.v[iter % 16] ^= accumulator;
        mix_block(&state_block);
        
        for (uint32_t i = 0; i < block_count; i++) {
            uint32_t idx_curr = (uint32_t)(((uint64_t)(memory_pool[i].v[0] ^ accumulator) * block_count) >> 32);
            uint32_t idx_prev = 0;
            if (iter > 0) {
                uint32_t pr2 = memory_pool[i].v[1] ^ state_block.v[(i+1) % 16];
                idx_prev = (uint32_t)(((uint64_t)pr2 * block_count) >> 32);
            }

            int use_prev = (iter % 2 == 0) ? (i < block_count / 2) : (i >= block_count / 2);
            uint32_t ref_idx = (iter > 0 && use_prev) ? idx_prev : idx_curr;

            xor_blocks(&tmp, &memory_pool[i], &memory_pool[ref_idx]);
            mix_block(&tmp);
            xor_blocks(&memory_pool[i], &memory_pool[i], &tmp);

            accumulator ^= memory_pool[i].v[0];
        }
    }

    for (uint32_t i = 0; i < block_count; i++) {
        state_block.v[i % 16] ^= i;
        xor_blocks(&state_block, &state_block, &memory_pool[i]);
        if ((i % 256) == 255) mix_block(&state_block);
    }
    mix_block(&state_block);

    memset(memory_pool, 0, block_count * sizeof(Block)); free(memory_pool);
    memset(digest, 0, 64);
    
    for (int i = 0; i < 16; i++) {
        uint32_t v = state_block.v[i];
        snprintf(out_hex + (i * 8), 9, "%02x%02x%02x%02x", (v >> 24) & 0xFF, (v >> 16) & 0xFF, (v >> 8) & 0xFF, v & 0xFF);
    }
    memset(&state_block, 0, sizeof(Block));
    return 0;
}


/* ========================================================================= *
 * 2. COMMAND LINE INTERFACE (CLI)                                           *
 * ========================================================================= */

void print_usage() {
    printf("\n");
    printf("========================================================\n");
    printf("        TARTARUS CLI (Password Hash Algorithm)              \n");
    printf("                         v1.0.0                             \n");
    printf("========================================================\n");
    printf("Usage:\n");
    printf("  tartarus_cli hash <password>\n");
    printf("      -> Generates a salt and hashes the password.\n\n");
    printf("  tartarus_cli verify <password> <salt_hex> <hash_hex>\n");
    printf("      -> Verifies if the password matches the hash.\n");
    printf("========================================================\n");
    printf("\n");
}

int main(int argc, char *argv[]) {
    const char *SERVER_PEPPER = getenv("TARTARUS_PEPPER");
    
    if (SERVER_PEPPER == NULL) {
        printf("[-] SECURITY ERROR: The environment variable 'TARTARUS_PEPPER' is missing.\n");
        printf("    Please configure it in your system's Environment Variables.\n");
        return 1;
    }

    if (argc < 3) {
        print_usage();
        return 1;
    }

    const char *command = argv[1];
    const char *password = argv[2];
    
    uint32_t mem_mb = 128; 
    uint32_t iter = 3;     

    if (strcmp(command, "hash") == 0) {
        printf("[*] Hashing a new password...\n");
        
        uint8_t salt_bytes[16];
        if (RAND_bytes(salt_bytes, sizeof(salt_bytes)) != 1) {
            printf("[-] Error: Failed to generate a secure salt via OpenSSL.\n");
            return 1;
        }

        char salt_hex[33]; 
        for (size_t i = 0; i < 16; i++) {
            sprintf(salt_hex + (i * 2), "%02x", salt_bytes[i]);
        }
        salt_hex[32] = '\0';

        char generated_hash[129];
        
        if (tartarus((const uint8_t*)password, strlen(password), 
                     (const uint8_t*)salt_hex, 32,
                     (const uint8_t*)SERVER_PEPPER, strlen(SERVER_PEPPER), 
                     mem_mb, iter, generated_hash) == 0) {
            
            printf("\n[+] SUCCESS! NEW PASSWORD SUCCESSFULLY HASHED.\n");
            printf("--------------------------------------------------------------------------------\n");
            printf("Salt : %s\n", salt_hex);
            printf("Hash : %s\n", generated_hash);
            printf("--------------------------------------------------------------------------------\n");
            
        } else {
            printf("[-] Fatal error in the cryptographic engine.\n");
        }

    } else if (strcmp(command, "verify") == 0) {
        if (argc < 5) {
            printf("[-] Error: Missing arguments for verification.\n");
            print_usage();
            return 1;
        }

        const char *salt_input = argv[3];
        const char *hash_input = argv[4];

        printf("[*] Computing Hash for verification (Parameters: %u MB, %u Iterations)...\n", mem_mb, iter);
        
        char computed_hash[129];
        
        if (tartarus((const uint8_t*)password, strlen(password), 
                     (const uint8_t*)salt_input, strlen(salt_input), 
                     (const uint8_t*)SERVER_PEPPER, strlen(SERVER_PEPPER), 
                     mem_mb, iter, computed_hash) == 0) {
            
            if (tartarus_verify(hash_input, computed_hash)) {
                printf("\n[+] ACCESS GRANTED: The password is valid! [MATCH]\n");
            } else {
                printf("\n[-] ACCESS DENIED: Incorrect password, Salt, or Hash. [MISMATCH]\n");
            }
        } else {
            printf("[-] Fatal error in the cryptographic engine.\n");
        }

    } else {
        printf("[-] Unrecognized command: %s\n", command);
        print_usage();
    }

    return 0;
}