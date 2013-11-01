
#include <botan/aes.h>
#include <botan/aes_ssse3.h>
#include <botan/keccak.h>
#include <botan/mode_pad.h>
#include <botan/xts.h>
#include <botan/md5.h>

#include <iostream>
#include <memory>

void TestAES()
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

    std::string user_data = "0123456789";

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

    if (dec_data != in_data)
    {
        std::cout << "AES: encrypt/decrypt fail!" << std::endl;
    }

#if !defined(_DEBUG) && !defined(DEBUG)
    Botan::AES_256_SSSE3 aes_ssse3;
    aes_ssse3.set_key(aes_key);
    aes.decrypt(out_data, dec_data);

    if (dec_data != in_data)
    {
        std::cout << "AES SSSE3: decrypt fail!" << std::endl;
    }
#endif
}

bool TestAES_XTS(
    std::shared_ptr<Botan::HashFunction> spHash, 
    std::shared_ptr<Botan::BlockCipher>  spCipher,
    const std::string &user_data)
{
    std::string password = "abc123456";
    spHash->update(password);
    auto hash_key = spHash->final();

    for (unsigned int i = 0; i < 1000; ++i)
    {
        spHash->update(static_cast<Botan::byte>(i));
        spHash->update(hash_key);
        hash_key = spHash->final();
    }

    spHash->clear();
    spHash->update("11001001");
    spHash->update(hash_key);
    auto xts_key = hash_key;
    xts_key += spHash->final(); // XTS: twice length of BlockCipher's key

    spHash->clear();
    spHash->update("003292323244232");
    spHash->update(hash_key);
    auto xts_nonce = spHash->final();
    auto xts_nonce_orig = xts_nonce;

    Botan::secure_vector<Botan::byte> in_data_orig(user_data.begin(), user_data.end());
    Botan::secure_vector<Botan::byte> in_data(in_data_orig);

    Botan::XTS_Encryption encryptor(spCipher->clone());
    encryptor.set_key(xts_key);
    auto nonce_size = encryptor.default_nonce_size();
    encryptor.start(xts_nonce.data(), nonce_size);
    encryptor.finish(in_data, 0);

    Botan::XTS_Decryption decryptor(spCipher->clone());
    decryptor.set_key(xts_key);
    nonce_size = decryptor.default_nonce_size();
    decryptor.start(xts_nonce.data(), nonce_size);
    decryptor.finish(in_data, 0);

    return in_data == in_data_orig;
}


int main()
{
    TestAES();

    // AES/XTS min 32 bytes (block size 16)
    std::string user_data = "abcdef0123456789abcdef0123456789"; 

    if (!TestAES_XTS(std::make_shared<Botan::Keccak_1600>(256),
                     std::make_shared<Botan::AES_256>(),
                     user_data))
    {
        std::cout << "ASE-256/XTS fail!" << std::endl;
    }

    if (!TestAES_XTS(std::make_shared<Botan::MD5>(),
                     std::make_shared<Botan::AES_128>(),
                     user_data))
    {
        std::cout << "ASE-128/XTS fail!" << std::endl;
    }
}


