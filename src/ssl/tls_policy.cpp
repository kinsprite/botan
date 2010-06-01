/**
* Policies for TLS
* (C) 2004-2010 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_policy.h>
#include <botan/tls_exceptn.h>

namespace Botan {

/**
* Return allowed ciphersuites
*/
std::vector<u16bit> TLS_Policy::ciphersuites() const
   {
   return suite_list(allow_static_rsa(), allow_edh_rsa(), allow_edh_dsa());
   }

/**
* Return allowed ciphersuites
*/
std::vector<u16bit> TLS_Policy::suite_list(bool use_rsa,
                                           bool use_edh_rsa,
                                           bool use_edh_dsa) const
   {
   std::vector<u16bit> suites;

   if(use_edh_dsa)
      {
      suites.push_back(TLS_DHE_DSS_WITH_AES_256_CBC_SHA);
      suites.push_back(TLS_DHE_DSS_WITH_AES_128_CBC_SHA);
      suites.push_back(TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA);
      suites.push_back(TLS_DHE_DSS_WITH_SEED_CBC_SHA);
      }

   if(use_edh_rsa)
      {
      suites.push_back(TLS_DHE_RSA_WITH_AES_256_CBC_SHA);
      suites.push_back(TLS_DHE_RSA_WITH_AES_128_CBC_SHA);
      suites.push_back(TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA);
      suites.push_back(TLS_DHE_RSA_WITH_SEED_CBC_SHA);
      }

   if(use_rsa)
      {
      suites.push_back(TLS_RSA_WITH_AES_256_CBC_SHA);
      suites.push_back(TLS_RSA_WITH_AES_128_CBC_SHA);
      suites.push_back(TLS_RSA_WITH_3DES_EDE_CBC_SHA);
      suites.push_back(TLS_RSA_WITH_SEED_CBC_SHA);
      suites.push_back(TLS_RSA_WITH_RC4_128_SHA);
      suites.push_back(TLS_RSA_WITH_RC4_128_MD5);
      }

   if(suites.size() == 0)
      throw TLS_Exception(INTERNAL_ERROR,
                          "TLS_Policy error: All ciphersuites disabled");

   return suites;
   }

/**
* Return allowed compression algorithms
*/
std::vector<byte> TLS_Policy::compression() const
   {
   std::vector<byte> algs;
   algs.push_back(NO_COMPRESSION);
   return algs;
   }

/**
* Choose which ciphersuite to use
*/
u16bit TLS_Policy::choose_suite(const std::vector<u16bit>& c_suites,
                                bool have_rsa,
                                bool have_dsa) const
   {
   bool use_static_rsa = allow_static_rsa() && have_rsa;
   bool use_edh_rsa = allow_edh_rsa() && have_rsa;
   bool use_edh_dsa = allow_edh_dsa() && have_dsa;

   std::vector<u16bit> s_suites = suite_list(use_static_rsa, use_edh_rsa,
                                             use_edh_dsa);

   for(u32bit j = 0; j != s_suites.size(); j++)
      for(u32bit k = 0; k != c_suites.size(); k++)
         if(s_suites[j] == c_suites[k])
            return s_suites[j];

   return 0;
   }

/**
* Choose which compression algorithm to use
*/
byte TLS_Policy::choose_compression(const std::vector<byte>& c_comp) const
   {
   std::vector<byte> s_comp = compression();

   for(u32bit j = 0; j != s_comp.size(); j++)
      for(u32bit k = 0; k != c_comp.size(); k++)
         if(s_comp[j] == c_comp[k])
            return s_comp[j];

   return NO_COMPRESSION;
   }

/**
* Return the group to use for empheral DH
*/
DL_Group TLS_Policy::dh_group() const
   {
   return DL_Group("modp/ietf/1024");
   }

/**
* Default certificate check
*/
bool TLS_Policy::check_cert(const std::vector<X509_Certificate>&,
                            const std::string&) const
   {
   return true;
   }

}