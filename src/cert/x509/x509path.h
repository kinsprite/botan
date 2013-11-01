/*
* X.509 Cert Path Validation
* (C) 2010-2011 Jack Lloyd
*
* Distributed under the terms of the Botan license
*/

#ifndef BOTAN_X509_CERT_PATH_VALIDATION_H__
#define BOTAN_X509_CERT_PATH_VALIDATION_H__

#include <botan/x509cert.h>
#include <botan/certstor.h>
#include <set>

namespace Botan {

/**
* Specifies restrictions on the PKIX path validation
*/
class BOTAN_DLL Path_Validation_Restrictions
   {
   public:
      /**
      * @param require_rev if true, revocation information is required
      * @param minimum_key_strength is the minimum strength (in terms of
      *        operations, eg 80 means 2^80) of a signature. Signatures
      *        weaker than this are rejected.
      */
      Path_Validation_Restrictions(bool require_rev = false,
                                   size_t minimum_key_strength = 80);

      /**
      * @param require_rev if true, revocation information is required
      * @param minimum_key_strength is the minimum strength (in terms of
      *        operations, eg 80 means 2^80) of a signature. Signatures
      *        weaker than this are rejected.
      * @param trusted_hashes a set of trusted hashes. Any signatures
      *        created using a hash other than one of these will be
      *        rejected.
      */
      Path_Validation_Restrictions(bool require_rev,
                                   size_t minimum_key_strength,
                                   const std::set<std::string>& trusted_hashes) :
         m_require_revocation_information(require_rev),
         m_trusted_hashes(trusted_hashes),
         m_minimum_key_strength(minimum_key_strength) {}

      bool require_revocation_information() const
         { return m_require_revocation_information; }

      const std::set<std::string>& trusted_hashes() const
         { return m_trusted_hashes; }

      size_t minimum_key_strength() const
         { return m_minimum_key_strength; }

   private:
      bool m_require_revocation_information;
      std::set<std::string> m_trusted_hashes;
      size_t m_minimum_key_strength;
   };

/**
* Represents the result of a PKIX path validation
*/

class BOTAN_DLL Path_Validation_Result;

/**
* PKIX Path Validation
*/
Path_Validation_Result BOTAN_DLL x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   const Path_Validation_Restrictions& restrictions,
   const std::vector<Certificate_Store*>& certstores);

class BOTAN_DLL Path_Validation_Result
   {
   public:
      /**
      * X.509 Certificate Validation Result
      */
      enum Code {
         VERIFIED,
         UNKNOWN_X509_ERROR,
         CANNOT_ESTABLISH_TRUST,
         CERT_CHAIN_TOO_LONG,
         SIGNATURE_ERROR,
         POLICY_ERROR,
         INVALID_USAGE,

         SIGNATURE_METHOD_TOO_WEAK,
         UNTRUSTED_HASH,

         CERT_MULTIPLE_ISSUERS_FOUND,

         CERT_FORMAT_ERROR,
         CERT_ISSUER_NOT_FOUND,
         CERT_NOT_YET_VALID,
         CERT_HAS_EXPIRED,
         CERT_IS_REVOKED,

         CRL_NOT_FOUND,
         CRL_FORMAT_ERROR,
         CRL_NOT_YET_VALID,
         CRL_HAS_EXPIRED,

         CA_CERT_CANNOT_SIGN,
         CA_CERT_NOT_FOR_CERT_ISSUER,
         CA_CERT_NOT_FOR_CRL_ISSUER
      };

      /**
      * @return the set of hash functions you are implicitly
      * trusting by trusting this result.
      */
      std::set<std::string> trusted_hashes() const;

      /**
      * @return the trust root of the validation
      */
      const X509_Certificate& trust_root() const;

      /**
      * @return the full path from subject to trust root
      */
      const std::vector<X509_Certificate>& cert_path() const { return m_cert_path; }

      /**
      * @return true iff the validation was succesful
      */
      bool successful_validation() const { return result() == VERIFIED; }

      /**
      * @return validation result code
      */
      Code result() const { return m_result; }

      /**
      * @return string representation of the validation result
      */
      std::string result_string() const;

   private:
      Path_Validation_Result() : m_result(UNKNOWN_X509_ERROR) {}

      friend Path_Validation_Result x509_path_validate(
         const std::vector<X509_Certificate>& end_certs,
         const Path_Validation_Restrictions& restrictions,
         const std::vector<Certificate_Store*>& certstores);

      void set_result(Code result) { m_result = result; }

      Code m_result;

      std::vector<X509_Certificate> m_cert_path;
   };

/**
* PKIX Path Validation
*/
Path_Validation_Result BOTAN_DLL x509_path_validate(
   const X509_Certificate& end_cert,
   const Path_Validation_Restrictions& restrictions,
   const std::vector<Certificate_Store*>& certstores);

/**
* PKIX Path Validation
*/
Path_Validation_Result BOTAN_DLL x509_path_validate(
   const X509_Certificate& end_cert,
   const Path_Validation_Restrictions& restrictions,
   const Certificate_Store& store);

/**
* PKIX Path Validation
*/
Path_Validation_Result BOTAN_DLL x509_path_validate(
   const std::vector<X509_Certificate>& end_certs,
   const Path_Validation_Restrictions& restrictions,
   const Certificate_Store& store);

}

#endif
