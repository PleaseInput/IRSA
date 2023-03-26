#pragma once
#include <iostream>
#include <assert.h>
#include "external include/cryptopp850/header/osrng.h"
#include "external include/cryptopp850/header/rsa.h"
#include "external include/cryptopp850/header/aes.h"
#include "external include/cryptopp850/header/base64.h"

std::string Encrypt(const std::string, CryptoPP::RSA::PublicKey);
std::string Decrypt(const std::string, CryptoPP::RSA::PrivateKey);

std::string string2hex(const std::string& str);
std::string hex2String(const std::string& hex);