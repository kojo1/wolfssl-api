#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <wolfssl/wolfcrypt/settings.h>

#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#define testingFmt "   %s:"
#define resultFmt " %s\n"
#include <wolfssl/test.h>
#include <tests/unit.h>

#ifdef WOLFSSL_TEST
#include <wolfssl/options.h>
#include <wolfssl/openssl/ssl.h>
#include <wolfssl/openssl/err.h>
#else
#include <openssl/ssl.h>
#include <openssl/err.h>
#endif

static void binary_dump(void *ptr, int size)
{
    #ifdef WOLFSSL_EVP_PRINT
   	int i = 0;
	unsigned char *p = (unsigned char *) ptr;

	printf("{");
	while((p != NULL) && (i < size)) {
		if((i % 8) == 0) {
			printf("\n");
			printf("    ");
		}
		printf("0x%02x, ", p[i]);
		i++;
	}
	printf("\n};\n");
    #else
    (void) ptr;
    (void) size;
    #endif
}

static int last_val = 0x0f;

static int check_result(unsigned char *data, int len)
{
	int i, j;
	
	for( ; len; ) {
		last_val = (last_val + 1) % 16;
		for(i = 0; i < 16; len--, i++, data++)
			if(*data != last_val) {
				printf("*data=%02x, last_val=%02x, i=%d, len=%d\n", 
				*data, last_val, i, len);
				return -1;
			}
	}
    return 0;
}

static int r_offset;
static int w_offset;

static void init_offset()
{
    r_offset = 0;
    w_offset = 0;
}
static void get_record(unsigned char *data, unsigned char *buf, int len)
{
    memcpy(buf, data+r_offset, len);
    r_offset += len;
}

static void set_record(unsigned char *data, unsigned char *buf, int len)
{
    memcpy(data+w_offset, buf, len);
    w_offset += len;
}

static void set_plain(unsigned char *plain, int rec)
{
    int i, j;
    unsigned char *p = plain;

    #define BLOCKSZ 16

    for(i=0; i<(rec/BLOCKSZ); i++){
        for(j=0; j<BLOCKSZ; j++)
            *p++ = (i % 16);
    }
    //binary_dump(plain, rec);
}

static int test_wolfSSL_EVP_Cipher(void)
{
    /* aes128-cbc, keylen=16, ivlen=16 */
    byte aes128_cbc_key[] = {
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
        0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef,
    };

    byte aes128_cbc_iv[] = {
        0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
        0x99, 0x00, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    };

    int test_drive0[] = {8, 3, 0};
    int test_drive1[] = {8, 3, 5, 512, 8, 3, 8, 512, 0};
    int test_drive2[] = {8, 3, 8, 512, 0};
    int test_drive3[] = {512, 512, 504, 512, 512, 8, 512, 0};

    int *test_drive[] = {test_drive0, test_drive2, test_drive3, NULL};
    int test_drive_len[100];
    int drive_len;

    int ret = 0;
	EVP_CIPHER_CTX *evp = NULL;
	
	int klen = 0;
    int i, j;

    const EVP_CIPHER *type = EVP_aes_128_cbc();
    byte *iv;
    byte *key;
    int keylen;

#define RECORDS 16
    #define BUFFSZ  512
    byte plain [BUFFSZ * RECORDS];
    byte cipher[BUFFSZ * RECORDS];

	byte inb[BUFFSZ];
	byte outb[BUFFSZ];
	int outl, inl;

	iv = aes128_cbc_iv;
	key = aes128_cbc_key;
	keylen = sizeof(aes128_cbc_key);
	type = EVP_aes_128_cbc();

    printf("Starting\n");
    set_plain(plain, BUFFSZ * RECORDS);
    printf("Plain Done\n");

#ifdef WOLFSSL_TEST
    wolfSSL_Debugging_ON();
#endif
	SSL_library_init();

    printf(testingFmt, "wolfSSL_EVP_Cipher");
    
    AssertNotNull(evp = EVP_CIPHER_CTX_new());
    AssertIntNE((ret = EVP_CipherInit(evp, type, NULL, iv, 0)), 0);

	klen = EVP_CIPHER_CTX_key_length(evp);
	if (klen > 0 && keylen != (u_int)klen) {
		AssertIntNE(EVP_CIPHER_CTX_set_key_length(evp, keylen), 0);
	}

    AssertIntNE((ret = EVP_CipherInit(evp, NULL, key, iv, 1)), 0);

    for (j = 0; j<RECORDS; j++)
    {
        inl = BUFFSZ;
        get_record(plain, inb, inl);
        //binary_dump(inb, inl);
        AssertIntNE((ret = EVP_CipherUpdate(evp, outb, &outl, inb, inl)), 0);
        set_record(cipher, outb, outl);
        //binary_dump(outb, outl);
    }

	for (i = 0; test_drive[i]; i++) {

		AssertIntNE((ret = EVP_CipherInit(evp, NULL, key, iv, 1)), 0);
        printf("Enc TEST #%d\n", i);
        init_offset();
        test_drive_len[i] = 0;

        for (j = 0; test_drive[i][j]; j++)
        {
            inl = test_drive[i][j];
            test_drive_len[i] += inl;

            get_record(plain, inb, inl);
            printf("inl=%d\n", inl);
    		//binary_dump(inb, inl);
			AssertIntNE((ret = EVP_EncryptUpdate(evp, outb, &outl, inb, inl)), 0);
			printf("outl=%d\n", outl);
            /* output to cipher buffer, so that following Dec test can detect
               if any error */
            set_record(cipher, outb, outl);
			//binary_dump(outb, outl);

			if (outl > (inl/16*(16 + 1)) && outl > 16) {
				printf("ERROR: outl=%d\n", outl);
				return 0;
			}
		}

		ret = EVP_CipherFinal(evp, outb, &outl);
        printf("ret=%d, outl=%d, test_drive_len[i]=%d\n", ret, outl, test_drive_len[i]);
        if(outl > 0)
            set_record(cipher, outb, outl);
    }

	for (i = 0; test_drive[i]; i++) {

		last_val = 0x0f;
        drive_len = 0;

		AssertIntNE((ret = EVP_CipherInit(evp, NULL, key, iv, 0)), 0);

        printf("Dec TEST #%d\n", i);
        init_offset();

		for (j = 0; test_drive[i][j]; j++){
			inl = test_drive[i][j];
			get_record(cipher, inb, inl);
			printf("inl=%d\n", inl);
			AssertIntNE((ret = EVP_DecryptUpdate(evp, outb, &outl, inb, inl)), 0);

			printf("ret=%d, outl=%d\n", ret, outl);
			binary_dump(outb, outl);
			AssertIntEQ((ret = check_result(outb, outl)), 0);
			AssertFalse(outl > ((inl/16+1)*16) && outl > 16);
            drive_len += inl;
        }

		ret = EVP_CipherFinal(evp, outb, &outl);
		printf("ret=%d, outl=%d\n", ret, outl);
        binary_dump(outb, outl);
        if (ret == 0)
        {
            drive_len += outl;
        }

        printf("drive_len=%d, test_drive_len[%d]=%d\n", drive_len, i, test_drive_len[i]);
        AssertTrue(drive_len == test_drive_len[i]);
    }

	EVP_CIPHER_CTX_free(evp);
    printf("END OF TEST\n");

	return 0;
}

int main(int argc, char **argv)
{
    test_wolfSSL_EVP_Cipher();
}
