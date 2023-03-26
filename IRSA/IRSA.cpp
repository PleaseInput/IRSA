// IRSA.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "IRSA.h"

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
    cipherBase64Enc = string2hex(cipher);
    std::cout << "cipher: " << cipherBase64Enc << std::endl;

    // Decryption
    std::string cipherBase64Dec;
    cipherBase64Dec = hex2String(cipherBase64Enc);

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

std::string string2hex(const std::string& str)
{
    static const char str2Hex[] = "0123456789ABCDEF";

    std::string hex;
    hex.reserve(str.size() * 2);

    for (size_t index = 0; index < str.size(); index++)
    {
        const char highValue = (str[index] >> 4) & 0x0F;
        hex.push_back(str2Hex[highValue]);

        const char lowValue = str[index] & 0x0F;
        hex.push_back(str2Hex[lowValue]);
    }

    return hex;
}

std::string hex2String(const std::string& hex)
{
    const size_t hexSize = hex.size();
    if (hexSize & 1)
    {
        throw std::invalid_argument("should be even length");
    }

    std::function<int(char)> convert2HexInt = [](const char c) {
        if ('0' <= c && c <= '9')
        {
            return c - '0';
        }
        else if ('a' <= c && c <= 'f')
        {
            return c - 'a' + 10;
        }
        else if ('A' <= c && c <= 'F')
        {
            return c - 'A' + 10;
        }
        else
        {
            throw std::invalid_argument("invalid char");
        }
    };

    std::string str;
    str.reserve(hexSize / 2);
    for (size_t index = 0; index < hexSize; index += 2)
    {
        const int highValue = convert2HexInt(hex[index + 0]) << 4;
        const int lowValue = convert2HexInt(hex[index + 1]);
        str.push_back(highValue | lowValue);
    }
    return str;
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