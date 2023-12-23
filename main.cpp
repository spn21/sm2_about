#include <stdio.h>
#include <gmssl/sm2.h>

int main(void) {
    SM2_KEY sm2_key;
    const char *password = "test sm2";
    const char *privateKeyFile = "private_key.pem";
    const char *publicKeyFile = "public_key.pem";

    if (sm2_key_generate(&sm2_key) != 1) {
        fprintf(stderr, "Error generating sm2_key\n");
        return -1;
    }

    // 将私钥信息加密并输出到文件
    FILE *privateKeyFilePtr = freopen(privateKeyFile, "w", stdout);
    if (!privateKeyFilePtr || sm2_private_key_info_encrypt_to_pem(&sm2_key, password, stdout) != 1) {
        fprintf(stderr, "Error saving encrypted private key to file\n");
        return -1;
    }
    fclose(privateKeyFilePtr);

    // 将公钥信息输出到文件
    FILE *publicKeyFilePtr = freopen(publicKeyFile, "w", stdout);
    if (!publicKeyFilePtr || sm2_public_key_info_to_pem(&sm2_key, stdout) != 1) {
        fprintf(stderr, "Error saving public key to file\n");
        return -1;
    }
    fclose(publicKeyFilePtr);

    // 从文件中读取并解密私钥信息
    FILE *readPrivateKeyFilePtr = freopen(privateKeyFile, "r", stdin);
    if (!readPrivateKeyFilePtr || sm2_private_key_info_decrypt_from_pem(&sm3_key, password, stdin) != 1) {
        fprintf(stderr, "Error reading and decrypting private key from file\n");
        return -1;
    }
    fclose(readPrivateKeyFilePtr);

    // 打印私钥信息
    printf("Decrypted Private Key: ");
    for (int i = 0; i < sizeof(sm2_key.private_key); i++) {
        printf("%02x", sm2_key.private_key[i]);
    }
    printf("\n");


    return 0;
}

