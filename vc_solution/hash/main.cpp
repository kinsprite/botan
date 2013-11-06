
#include <botan/keccak.h>
#include <botan/md5.h>
#include <botan/sha160.h>
#include <botan/sha2_32.h>
#include <botan/sha2_64.h>

#include <iostream>

void PrintHashVec(const std::string &str, const Botan::secure_vector<Botan::byte> vec)
{
    std::cout << str;

    for (auto v : vec)
    {
        const char hexChar[] = "0123456789abcdef";

        std::cout << hexChar[v >> 4] << hexChar[v & 0x0F];
    }

    std::cout << std::endl;
}

int main()
{
    std::string str = "abcdefg0123456789";
    std::cout << "Calc hash of \"" << str << "\"." << std::endl;
    PrintHashVec("MD5: ", Botan::MD5().process(str));
    PrintHashVec("SHA-1: ", Botan::SHA_160().process(str));
    PrintHashVec("SHA-256: ", Botan::SHA_256().process(str));
    PrintHashVec("SHA-512: ", Botan::SHA_512().process(str));
    PrintHashVec("SHA3-256: ", Botan::Keccak_1600(256).process(str));
    PrintHashVec("SHA3-512: ", Botan::Keccak_1600(512).process(str));
}
