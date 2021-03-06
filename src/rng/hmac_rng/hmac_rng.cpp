/*
* HMAC_RNG
* (C) 2008-2009 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#include <botan/hmac_rng.h>
#include <botan/get_byte.h>
#include <botan/internal/xor_buf.h>
#include <algorithm>

namespace Botan {

namespace {

void hmac_prf(MessageAuthenticationCode* prf,
              secure_vector<byte>& K,
              u32bit& counter,
              const std::string& label)
   {
   prf->update(K);
   prf->update(label);
   prf->update_be(counter);
   prf->final(&K[0]);

   ++counter;
   }

}

/*
* Generate a buffer of random bytes
*/
void HMAC_RNG::randomize(byte out[], size_t length)
   {
   if(!is_seeded())
      throw PRNG_Unseeded(name());

   /*
    HMAC KDF as described in E-t-E, using a CTXinfo of "rng"
   */
   while(length)
      {
      hmac_prf(prf, K, counter, "rng");

      const size_t copied = std::min<size_t>(K.size() / 2, length);

      copy_mem(out, &K[0], copied);
      out += copied;
      length -= copied;

      if(counter % 1024 == 0)
         reseed(128);
      }
   }

/*
* Poll for entropy and reset the internal keys
*/
void HMAC_RNG::reseed(size_t poll_bits)
   {
   /*
   Using the terminology of E-t-E, XTR is the MAC function (normally
   HMAC) seeded with XTS (below) and we form SKM, the key material, by
   polling as many sources as we think needed to reach our polling
   goal. We then also include feedback of the current PRK so that
   a bad poll doesn't wipe us out.
   */

   Entropy_Accumulator_BufferedComputation accum(*extractor, poll_bits);

   if(!entropy_sources.empty())
      {
      size_t poll_attempt = 0;

      while(!accum.polling_goal_achieved() && poll_attempt < poll_bits)
         {
         const size_t src_idx = poll_attempt % entropy_sources.size();
         entropy_sources[src_idx]->poll(accum);
         ++poll_attempt;
         }
      }

   /*
   * It is necessary to feed forward poll data. Otherwise, a good poll
   * (collecting a large amount of conditional entropy) followed by a
   * bad one (collecting little) would be unsafe. Do this by
   * generating new PRF outputs using the previous key and feeding
   * them into the extractor function.
   *
   * Cycle the RNG once (CTXinfo="rng"), then generate a new PRF
   * output using the CTXinfo "reseed". Provide these values as input
   * to the extractor function.
   */
   hmac_prf(prf, K, counter, "rng");
   extractor->update(K); // K is the CTXinfo=rng PRF output

   hmac_prf(prf, K, counter, "reseed");
   extractor->update(K); // K is the CTXinfo=reseed PRF output

   /* Now derive the new PRK using everything that has been fed into
      the extractor, and set the PRF key to that */
   prf->set_key(extractor->final());

   // Now generate a new PRF output to use as the XTS extractor salt
   hmac_prf(prf, K, counter, "xts");
   extractor->set_key(K);

   // Reset state
   zeroise(K);

   /*
   * Consider ourselves seeded once we've collected an estimated 128 bits of
   * entropy in a single poll.
   */
   if(seeded == false && accum.bits_collected() >= 128)
      seeded = true;
   }

/*
* Add user-supplied entropy to the extractor input
*/
void HMAC_RNG::add_entropy(const byte input[], size_t length)
   {
   /*
   * Simply include the data in the extractor input. During the
   * next periodic reseed, the input will be incorporated into
   * the state.
   */
   extractor->update(input, length);
   }

/*
* Add another entropy source to the list
*/
void HMAC_RNG::add_entropy_source(EntropySource* src)
   {
   entropy_sources.push_back(src);
   }

/*
* Clear memory of sensitive data
*/
void HMAC_RNG::clear()
   {
   extractor->clear();
   prf->clear();
   zeroise(K);
   counter = 0;
   seeded = false;
   }

/*
* Return the name of this type
*/
std::string HMAC_RNG::name() const
   {
   return "HMAC_RNG(" + extractor->name() + "," + prf->name() + ")";
   }

/*
* HMAC_RNG Constructor
*/
HMAC_RNG::HMAC_RNG(MessageAuthenticationCode* extractor_mac,
                   MessageAuthenticationCode* prf_mac) :
   extractor(extractor_mac), prf(prf_mac)
   {
   if(!prf->valid_keylength(extractor->output_length()) ||
      !extractor->valid_keylength(prf->output_length()))
      throw Invalid_Argument("HMAC_RNG: Bad algo combination " +
                             extractor->name() + " and " +
                             prf->name());

   // First PRF inputs are all zero, as specified in section 2
   K.resize(prf->output_length());

   counter = 0;
   seeded = false;

   /*
   Normally we want to feedback PRF output into the input to the
   extractor function to ensure a single bad poll does not damage the
   RNG, but obviously that is meaningless to do on the first poll.

   We will want to use the PRF before we set the first key (in
   reseed), and it is a pain to keep track if it is set or
   not. Since the first time it doesn't matter anyway, just set the
   PRF key to constant zero: randomize() will not produce output
   unless is_seeded() returns true, and that will only be the case if
   the estimated entropy counter is high enough. That variable is only
   set when a reseeding is performed.
   */
   secure_vector<byte> prf_key(extractor->output_length());
   prf->set_key(prf_key);

   /*
   Use PRF("Botan HMAC_RNG XTS") as the intitial XTS key.

   This will be used during the first extraction sequence; XTS values
   after this one are generated using the PRF.

   If I understand the E-t-E paper correctly (specifically Section 4),
   using this fixed extractor key is safe to do.
   */
   extractor->set_key(prf->process("Botan HMAC_RNG XTS"));
   }

/*
* HMAC_RNG Destructor
*/
HMAC_RNG::~HMAC_RNG()
   {
   delete extractor;
   delete prf;

   for(auto src : entropy_sources)
     delete src;

   counter = 0;
   }

}
