#include "chacha20.h"

#define DEBUG 1
#define METHOD 1

uint32_t state[16];

/*
useful modules for printing and endianness
*/
void print_state(uint32_t *state)
{
    for (int i = 0; i < 16; i++)
    {
        printf("%08x ", state[i]);
        if (i % 4 == 3)
            printf("\n");
    }
    printf("\n");
}

void hex_to_uint32(char *hex, uint32_t *arr, int len)
{
    for (int i = 0; i < len; i++)
    {
        sscanf(hex + 8 * i, "%08x", &arr[i]);
    }
    // reverse endian
    for (int i = 0; i < len; i++)
    {
        arr[i] = ((arr[i] & 0x000000ff) << 24) | ((arr[i] & 0x0000ff00) << 8) | ((arr[i] & 0x00ff0000) >> 8) | ((arr[i] & 0xff000000) >> 24);
    }
}

void print_uint32(uint32_t *arr, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%08x ", arr[i]);
    }
    printf("\n");
}

void print_output(char *output, int len)
{
    for (int i = 0; i < len; i++)
    {
        printf("%02x", output[i]);
        if (i % 2 == 1)
            printf(" ");
        if (i % 32 == 31)
            printf("\n");
    }
    printf("\n");
}

/*
chacha20 implementation
*/
void quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d)
{
    *a += *b;
    *d ^= *a;
    *d = (*d << 16) | (*d >> 16);
    *c += *d;
    *b ^= *c;
    *b = (*b << 12) | (*b >> 20);
    *a += *b;
    *d ^= *a;
    *d = (*d << 8) | (*d >> 24);
    *c += *d;
    *b ^= *c;
    *b = (*b << 7) | (*b >> 25);
}

void init_state(uint32_t *state, uint32_t *key, uint32_t *nonce, uint32_t counter)
{
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;

    state[4] = key[0];
    state[5] = key[1];
    state[6] = key[2];
    state[7] = key[3];
    state[8] = key[4];
    state[9] = key[5];
    state[10] = key[6];
    state[11] = key[7];

    state[12] = counter;

    state[13] = nonce[0];
    state[14] = nonce[1];
    state[15] = nonce[2];
}

void block_round(uint32_t *state)
{
    quarter_round(&state[0], &state[4], &state[8], &state[12]);
    quarter_round(&state[1], &state[5], &state[9], &state[13]);
    quarter_round(&state[2], &state[6], &state[10], &state[14]);
    quarter_round(&state[3], &state[7], &state[11], &state[15]);
    quarter_round(&state[0], &state[5], &state[10], &state[15]);
    quarter_round(&state[1], &state[6], &state[11], &state[12]);
    quarter_round(&state[2], &state[7], &state[8], &state[13]);
    quarter_round(&state[3], &state[4], &state[9], &state[14]);
}

void chacha20_block(uint32_t *state, uint32_t *key, uint32_t *nonce, uint32_t counter)
{
    init_state(state, key, nonce, counter);
#if DEBUG
    printf("\ninitial state:\n");
    print_state(state);
#endif

    uint32_t initial_state[16];
    memcpy(initial_state, state, 16 * sizeof(uint32_t));
    for (int i = 0; i < 10; i++)
    {
        block_round(state);
    }
    for (int i = 0; i < 16; i++)
    {
        state[i] += initial_state[i];
    }
}

void serialize_state(uint32_t *state, char *output)
{
    for (int i = 0; i < 16; i++)
    { // reverse endian
        state[i] = ((state[i] & 0x000000ff) << 24) | ((state[i] & 0x0000ff00) << 8) | ((state[i] & 0x00ff0000) >> 8) | ((state[i] & 0xff000000) >> 24);
    }
    for (int i = 0; i < 16; i++)
    {
        sprintf(output + 8 * i, "%08x", state[i]);
    }
}

void chacha20_encrypt(uint32_t key_arr[8], uint32_t nonce_arr[3], uint32_t counter, unsigned char *plaintext, char *ciphertext, FILE *output_file)
{

    uint32_t keystream[16];
    int len = strlen(plaintext);
    int block_num = len / 64;
    int remain = len % 64;

    for (int i = 0; i < block_num; i++)
    {
        chacha20_block(keystream, key_arr, nonce_arr, counter + i); // apply stream cipher
#if DEBUG
        printf("\nkeystream for block %d:\n", i);
        print_state(keystream);
#endif

        for (int j = 0; j < 16; j++)
        { // reverse endian for keystream
            keystream[j] = ((keystream[j] & 0x000000ff) << 24) | ((keystream[j] & 0x0000ff00) << 8) | ((keystream[j] & 0x00ff0000) >> 8) | ((keystream[j] & 0xff000000) >> 24);
        }
#if DEBUG
        printf("after endian:\n");
        print_state(keystream);
#endif
        for (int j = 0; j < 16; j++)
        {
            #if DEBUG
            printf("%08x ", keystream[j]);
            printf("%08x ", (plaintext[64 * i + 4 * j] << 24 | plaintext[64 * i + 4 * j + 1] << 16 | plaintext[64 * i + 4 * j + 2] << 8 | plaintext[64 * i + 4 * j + 3]));
            printf("%08x ", keystream[j] ^ (plaintext[64 * i + 4 * j] << 24 | plaintext[64 * i + 4 * j + 1] << 16 | plaintext[64 * i + 4 * j + 2] << 8 | plaintext[64 * i + 4 * j + 3]));
            printf("\n");
            #endif

            uint32_t c = keystream[j] ^ (plaintext[64 * i + 4 * j] << 24 | plaintext[64 * i + 4 * j + 1] << 16 | plaintext[64 * i + 4 * j + 2] << 8 | plaintext[64 * i + 4 * j + 3]);
            c = ((c & 0x000000ff) << 24) | ((c & 0x0000ff00) << 8) | ((c & 0x00ff0000) >> 8) | ((c & 0xff000000) >> 24);
            fwrite(&c, 1, 4, output_file);
        }
    }
    if (remain != 0)
    {
        chacha20_block(keystream, key_arr, nonce_arr, counter + block_num); // apply stream cipher
#if DEBUG
        printf("\nkeystream for remain :\n");
        print_state(keystream);
#endif
        for (int j = 0; j < 16; j++)
        { // reverse endian for keystream
            keystream[j] = ((keystream[j] & 0x000000ff) << 24) | ((keystream[j] & 0x0000ff00) << 8) | ((keystream[j] & 0x00ff0000) >> 8) | ((keystream[j] & 0xff000000) >> 24);
        }
        for (int j = 0; j < (remain / 4) ; j++)
        {
            uint32_t c = keystream[j] ^ (plaintext[64 * block_num + 4 * j] << 24 | plaintext[64 * block_num + 4 * j + 1] << 16 | plaintext[64 * block_num + 4 * j + 2] << 8 | plaintext[64 * block_num + 4 * j + 3]);
            c = ((c & 0x000000ff) << 24) | ((c & 0x0000ff00) << 8) | ((c & 0x00ff0000) >> 8) | ((c & 0xff000000) >> 24);
            fwrite(&c, 1, 4, output_file);
        }
        uint32_t c = keystream[remain / 4] ^ (plaintext[64 * block_num + 4 * (remain / 4)] << 24 | plaintext[64 * block_num + 4 * (remain / 4) + 1] << 16 | plaintext[64 * block_num + 4 * (remain / 4) + 2] << 8 | plaintext[64 * block_num + 4 * (remain / 4) + 3]);
            c = ((c & 0x000000ff) << 24) | ((c & 0x0000ff00) << 8) | ((c & 0x00ff0000) >> 8) | ((c & 0xff000000) >> 24);
            fwrite(&c, 1, (len % 4), output_file);
    }
}

void chacha20_encrypt_keystream(uint32_t **keystream, uint32_t key_arr[8], uint32_t nonce_arr[3], uint32_t counter, int len)
{
    int block_num = len / 64;
    int remain = len % 64;

    for (int i = 0; i < block_num; i++)
    {
        chacha20_block(keystream[i], key_arr, nonce_arr, counter + i); // apply stream cipher
#if DEBUG
        printf("\nkeystream for block %d:\n", i);
        print_state(keystream[i]);
#endif

        for (int j = 0; j < 16; j++)
        { // reverse endian for keystream
            keystream[i][j] = ((keystream[i][j] & 0x000000ff) << 24) | ((keystream[i][j] & 0x0000ff00) << 8) | ((keystream[i][j] & 0x00ff0000) >> 8) | ((keystream[i][j] & 0xff000000) >> 24);
        }
#if DEBUG
        printf("after endian:\n");
        print_state(keystream[i]);
#endif
    }
    if (remain != 0)
    {
        chacha20_block(keystream[block_num], key_arr, nonce_arr, counter + block_num); // apply stream cipher
        for (int j = 0; j < 16; j++)
        { // reverse endian for keystream
            keystream[block_num][j] = ((keystream[block_num][j] & 0x000000ff) << 24) | ((keystream[block_num][j] & 0x0000ff00) << 8) | ((keystream[block_num][j] & 0x00ff0000) >> 8) | ((keystream[block_num][j] & 0xff000000) >> 24);
        }
#if DEBUG
        printf("\nkeystream for remain :\n");
        print_state(keystream[block_num]);
#endif
    }
}

/*
tesing module
*/
void test_quarter_round()
{
    uint32_t a = 0x11111111;
    uint32_t b = 0x01020304;
    uint32_t c = 0x9b8d6f43;
    uint32_t d = 0x01234567;

    quarter_round(&a, &b, &c, &d);
    printf("-------- section 2.1: quarter round test --------\n\n");
    if (a == 0xea2a92f4)
        printf("a: PASS\n");
    else
        printf("a: FAIL\n");
    if (b == 0xcb1cf8ce)
        printf("b: PASS\n");
    else
        printf("b: FAIL\n");
    if (c == 0x4581472e)
        printf("c: PASS\n");
    else
        printf("c: FAIL\n");
    if (d == 0x5881c4bb)
        printf("d: PASS\n");
    else
        printf("d: FAIL\n");
    printf("------------------------------------\n\n");
}

void test_qr_state()
{
    uint32_t rand_state[16] = {0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
                               0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
                               0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
                               0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320};
    printf("-------- section 2.2: quarter round state test --------\n\n");
    quarter_round(&rand_state[2], &rand_state[7], &rand_state[8], &rand_state[13]);
    print_state(rand_state);
    if (rand_state[2] == 0xbdb886dc)
        printf("state[2]: PASS\n");
    else
        printf("state[2]: FAIL\n");
    if (rand_state[7] == 0xcfacafd2)
        printf("state[7]: PASS\n");
    else
        printf("state[7]: FAIL\n");
    if (rand_state[8] == 0xe46bea80)
        printf("state[8]: PASS\n");
    else
        printf("state[8]: FAIL\n");
    if (rand_state[13] == 0xccc07c79)
        printf("state[13]: PASS\n");
    else
        printf("state[13]: FAIL\n");
    printf("------------------------------------------\n\n");
}

void test_chacha20_block()
{
    char *key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    char *nonce = "000000090000004a00000000";
    uint32_t counter = 1;
    uint32_t key_arr[8];
    uint32_t nonce_arr[3];
    uint32_t state[16];
    printf("-------- section 2.3: chacha20 block test --------\n\n");
    hex_to_uint32(key, key_arr, 8);
    hex_to_uint32(nonce, nonce_arr, 3);
    printf("key: ");
    print_uint32(key_arr, 8);
    printf("\nnonce: ");
    print_uint32(nonce_arr, 3);

    chacha20_block(state, key_arr, nonce_arr, counter);
    printf("final state:\n");
    print_state(state);

    char output[128];
    serialize_state(state, output);
    printf("output: \n");
    print_output(output, strlen(output));
    printf("-------------------------------------\n\n");
}

void test_encryption()
{
    char *key = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    char *nonce = "000000000000004a00000000";
    uint32_t counter = 1;
    uint32_t key_arr[8];
    uint32_t nonce_arr[3];
    uint32_t state[16];
    printf("-------- section 2.4: chacha20 encryption test --------\n\n");
    hex_to_uint32(key, key_arr, 8);
    hex_to_uint32(nonce, nonce_arr, 3);

    char *plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    char ciphertext[strlen(plaintext) * 2 + 1];
    // chacha20_encrypt(key_arr, nonce_arr, counter, plaintext, ciphertext);
    print_output(ciphertext, strlen(plaintext) * 2);
    printf("-------------------------------------\n\n");
}

int main(int argc, char *argv[])
{

#if DEBUG

    // // section 2.1
    // test_quarter_round(); // --passed
    // // section 2.2
    // test_qr_state(); // --passed
    // // section 2.3
    // test_chacha20_block(); // --passed
    // // section 2.4
    // test_encryption(); // --passed

#endif

    // read 4 args : chacha20 keyfile.bin NONCE input.txt my_ciphertext.bin
    if (argc != 5)
    {
        printf("Usage: chacha20 keyfile.bin NONCE input.bin my_ciphertext.bin\n");
        return 1;
    }

    // key
    FILE *keyfile = fopen(argv[1], "rb");
    uint32_t key[8];
    if (keyfile == NULL)
    {
        printf("Error: could not open keyfile\n");
        return 1;
    }
    fread(key, sizeof(uint32_t), 8, keyfile);
    fclose(keyfile);

    // NONCE
    char *nonce = argv[2];
    uint32_t nonce_arr[3];
    hex_to_uint32(nonce, nonce_arr, 3);

#if METHOD == 1
    FILE *input = fopen(argv[3], "rb");
    if (input == NULL)
    {
        printf("Error: could not open input file\n");
        return 1;
    }
    fseek(input, 0, SEEK_END);
    int len = ftell(input);
    fseek(input, 0, SEEK_SET);

    unsigned char *plaintext = (char *)malloc(len);
    fread(plaintext, 1, len, input);
    fclose(input);

    // encrypt

    FILE *output = fopen(argv[4], "wb");
    if (output == NULL)
    {
        printf("Error: could not open output file\n");
        return 1;
    }
    uint32_t counter = 1;

    char ciphertext[len * 2 + 1];
    chacha20_encrypt(key, nonce_arr, counter, plaintext, ciphertext, output);

    fclose(output);

    free(plaintext);

#endif

#if METHOD == 2
    FILE *input = fopen(argv[3], "rb");
    if (input == NULL)
    {
        printf("Error: could not open input file\n");
        return 1;
    }
    fseek(input, 0, SEEK_END);
    int len = ftell(input);
    fseek(input, 0, SEEK_SET);

    int block_num = len / 64 + 1;
    uint32_t **keystream = (uint32_t **)malloc(block_num * sizeof(uint32_t *));
    for (int i = 0; i < block_num; i++)
    {
        keystream[i] = (uint32_t *)malloc(16 * sizeof(uint32_t));
    }

    uint32_t counter = 1;
    chacha20_encrypt_keystream(keystream, key, nonce_arr, counter, len);

#if DEBUG
    printf("keystream final :\n");

    for (int i = 0; i < block_num; i++)
    {
        print_state(keystream[i]);
        printf("\n");
    }
    printf("end demo\n");
#endif

    uint32_t c;

    printf("----------------\n");
    unsigned char *output = (char *)malloc(len);
    int i = 0;
    while (c = fgetc(input), c != EOF)
    {
        output[i] = c;
        i++;
    }

    fclose(input);
    for (int i = 0; i < len; i++)
    {
        printf("%c", output[i]);
        if (i % 2 == 1)
            printf(" ");
        if (i % 32 == 31)
            printf("\n");
    }

#endif
    return 0;
}