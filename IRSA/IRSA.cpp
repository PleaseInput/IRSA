// IRSA.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include "external include/cryptopp850/header/osrng.h"
#include "external include/cryptopp850/header/rsa.h"
#include "external include/cryptopp850/header/aes.h"
#include "external include/cryptopp850/header/base64.h"

std::string Encrypt(const std::string, CryptoPP::RSA::PublicKey);
std::string Decrypt(const std::string, CryptoPP::RSA::PrivateKey);

int main()
{
    // Generate keys
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::InvertibleRSAFunction params;
    params.GenerateRandomWithKeySize(rng, 1024 /*2048*/);

    const CryptoPP::Integer& n = params.GetModulus();
    const CryptoPP::Integer& p = params.GetPrime1();
    const CryptoPP::Integer& q = params.GetPrime2();
    const CryptoPP::Integer& d = params.GetPrivateExponent();
    const CryptoPP::Integer& e = params.GetPublicExponent();

    std::cout << " n: " << n << std::endl;
    std::cout << " p: " << p << std::endl;
    std::cout << " q: " << q << std::endl;
    std::cout << " d: " << d << std::endl;
    std::cout << " e: " << e << std::endl;

    CryptoPP::RSA::PrivateKey privateKey(params);
    CryptoPP::RSA::PublicKey publicKey(params);

    // Encryption
    const std::string plain = "Test string";
    std::string cipher = Encrypt(plain, publicKey);
    std::string cipherBase64Enc;
    CryptoPP::StringSource ssEncrypto(
        cipher.c_str(),
        true,
        new CryptoPP::Base64Encoder(
            new CryptoPP::StringSink(cipherBase64Enc)
        )
    );
    std::cout << "cipher: " << cipherBase64Enc << std::endl;

    // Decryption
    std::string cipherBase64Dec;
    CryptoPP::StringSource ssDecrypto(
        cipherBase64Enc.c_str(),
        true,
        new CryptoPP::Base64Decoder(
            new CryptoPP::StringSink(cipherBase64Dec)
        )
    );
    std::string recoverd = Decrypt(cipherBase64Dec, privateKey);
    std::cout << "recoverd: " << recoverd << std::endl;

    return 0;
}

std::string Encrypt(const std::string plain, CryptoPP::RSA::PublicKey publicKey)
{
    std::string cipher;
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Encryptor encryptor(publicKey);
    CryptoPP::StringSink* pStringSinkEncrypt = new CryptoPP::StringSink(cipher);
    CryptoPP::PK_EncryptorFilter* pPK_EncryptorFilter = new CryptoPP::PK_EncryptorFilter(rng, encryptor, pStringSinkEncrypt);
    CryptoPP::StringSource stringSourceEncrypt(plain, true, pPK_EncryptorFilter);

    return cipher;
}

std::string Decrypt(const std::string cipher, CryptoPP::RSA::PrivateKey privateKey)
{
    std::string recoverd;
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::RSAES_OAEP_SHA_Decryptor decryptor(privateKey);
    CryptoPP::StringSink* pStringSinkDecrypt = new CryptoPP::StringSink(recoverd);
    CryptoPP::PK_DecryptorFilter* pPK_DecryptorFilter = new CryptoPP::PK_DecryptorFilter(rng, decryptor, pStringSinkDecrypt);
    CryptoPP::StringSource stringSourceEncrypt(cipher, true, pPK_DecryptorFilter);

    return recoverd;
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file