
#include <botan/aes.h>
#include <botan/aes_ssse3.h>
#include <botan/keccak.h>

#include <iostream>

int main()
{
    std::string password = "abc123456";
    Botan::Keccak_1600 hash(256);
    hash.update(password);
    auto aes_key = hash.final();

    for (unsigned int i = 0; i < 1000; ++i)
    {
        hash.update(static_cast<Botan::byte>(i));
        hash.update(aes_key);
        aes_key = hash.final();
    }

    Botan::AES_256 aes;
    aes.set_key(aes_key);

    std::string user_data = "abcdef0123456789123456789";

    std::vector<Botan::byte> in_data(user_data.begin(), user_data.end());

    if (in_data.size() % aes.block_size())
    {
        in_data.resize((in_data.size() / aes.block_size() + 1) * aes.block_size());
    }

    std::vector<Botan::byte> out_data(in_data.size());
    aes.encrypt(in_data, out_data);

    std::vector<Botan::byte> dec_data(out_data.size());
    aes.clear();
    aes.set_key(aes_key);
    aes.decrypt(out_data, dec_data);

    std::cout << "AES Encrypt/Eecrypt" << std::endl;

    if (dec_data != in_data)
    {
        std::cout << "AES: encrypt/decrypt error." << std::endl;
    }

    Botan::AES_256_SSSE3 aes_ssse3;
    aes_ssse3.set_key(aes_key);
    aes.decrypt(out_data, dec_data);

    if (dec_data != in_data)
    {
        std::cout << "AES SSSE3: decrypt error." << std::endl;
    }
}

