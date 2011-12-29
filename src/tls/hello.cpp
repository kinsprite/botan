/*
* TLS Hello Messages
* (C) 2004-2011 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/internal/tls_messages.h>
#include <botan/internal/tls_reader.h>
#include <botan/internal/tls_session_key.h>
#include <botan/internal/tls_extensions.h>
#include <botan/tls_record.h>

#include <stdio.h>

namespace Botan {

/*
* Encode and send a Handshake message
*/
void HandshakeMessage::send(Record_Writer& writer, TLS_Handshake_Hash& hash) const
   {
   MemoryVector<byte> buf = serialize();
   MemoryVector<byte> send_buf(4);

   const size_t buf_size = buf.size();

   send_buf[0] = type();

   for(size_t i = 1; i != 4; ++i)
     send_buf[i] = get_byte<u32bit>(i, buf_size);

   send_buf += buf;

   hash.update(send_buf);

   writer.send(HANDSHAKE, &send_buf[0], send_buf.size());
   }

/*
* Create a new Hello Request message
*/
Hello_Request::Hello_Request(Record_Writer& writer)
   {
   TLS_Handshake_Hash dummy; // FIXME: *UGLY*
   send(writer, dummy);
   }

/*
* Serialize a Hello Request message
*/
MemoryVector<byte> Hello_Request::serialize() const
   {
   return MemoryVector<byte>();
   }

/*
* Deserialize a Hello Request message
*/
void Hello_Request::deserialize(const MemoryRegion<byte>& buf)
   {
   if(buf.size())
      throw Decoding_Error("Hello_Request: Must be empty, and is not");
   }

/*
* Create a new Client Hello message
*/
Client_Hello::Client_Hello(Record_Writer& writer,
                           TLS_Handshake_Hash& hash,
                           const TLS_Policy& policy,
                           RandomNumberGenerator& rng,
                           const std::string& hostname,
                           const std::string& srp_identifier) :
   c_version(policy.pref_version()),
   c_random(rng.random_vec(32)),
   suites(policy.ciphersuites()),
   comp_methods(policy.compression()),
   requested_hostname(hostname),
   requested_srp_id(srp_identifier)
   {
   send(writer, hash);
   }

/*
* Serialize a Client Hello message
*/
MemoryVector<byte> Client_Hello::serialize() const
   {
   MemoryVector<byte> buf;

   buf.push_back(static_cast<byte>(c_version >> 8));
   buf.push_back(static_cast<byte>(c_version     ));
   buf += c_random;

   append_tls_length_value(buf, sess_id, 1);
   append_tls_length_value(buf, suites, 2);
   append_tls_length_value(buf, comp_methods, 1);

   printf("Requesting hostname '%s'\n", requested_hostname.c_str());

   /*
   * May not want to send extensions at all in some cases.
   * If so, should include SCSV value
   */

   TLS_Extensions extensions;
   extensions.push_back(new Renegotation_Extension());
   extensions.push_back(new Server_Name_Indicator(requested_hostname));
   extensions.push_back(new SRP_Identifier(requested_srp_id));
   buf += extensions.serialize();

   return buf;
   }

void Client_Hello::deserialize_sslv2(const MemoryRegion<byte>& buf)
   {
   if(buf.size() < 12 || buf[0] != 1)
      throw Decoding_Error("Client_Hello: SSLv2 hello corrupted");

   const size_t cipher_spec_len = make_u16bit(buf[3], buf[4]);
   const size_t sess_id_len = make_u16bit(buf[5], buf[6]);
   const size_t challenge_len = make_u16bit(buf[7], buf[8]);

   const size_t expected_size =
      (9 + sess_id_len + cipher_spec_len + challenge_len);

   if(buf.size() != expected_size)
      throw Decoding_Error("Client_Hello: SSLv2 hello corrupted");

   if(sess_id_len != 0 || cipher_spec_len % 3 != 0 ||
      (challenge_len < 16 || challenge_len > 32))
      {
      throw Decoding_Error("Client_Hello: SSLv2 hello corrupted");
      }

   for(size_t i = 9; i != 9 + cipher_spec_len; i += 3)
      {
      if(buf[i] != 0) // a SSLv2 cipherspec; ignore it
         continue;

      suites.push_back(make_u16bit(buf[i+1], buf[i+2]));
      }

   c_version = static_cast<Version_Code>(make_u16bit(buf[1], buf[2]));

   c_random.resize(challenge_len);
   copy_mem(&c_random[0], &buf[9+cipher_spec_len+sess_id_len], challenge_len);
   }

/*
* Deserialize a Client Hello message
*/
void Client_Hello::deserialize(const MemoryRegion<byte>& buf)
   {
   has_secure_renegotiation = false;

   if(buf.size() == 0)
      throw Decoding_Error("Client_Hello: Packet corrupted");

   if(buf.size() < 41)
      throw Decoding_Error("Client_Hello: Packet corrupted");

   TLS_Data_Reader reader(buf);

   c_version = static_cast<Version_Code>(reader.get_u16bit());
   c_random = reader.get_fixed<byte>(32);

   sess_id = reader.get_range<byte>(1, 0, 32);

   suites = reader.get_range_vector<u16bit>(2, 1, 32767);

   comp_methods = reader.get_range_vector<byte>(1, 1, 255);

   TLS_Extensions extensions(reader);

   for(size_t i = 0; i != extensions.count(); ++i)
      {
      TLS_Extension* extn = extensions.at(i);

      if(Server_Name_Indicator* sni = dynamic_cast<Server_Name_Indicator*>(extn))
         requested_hostname = sni->host_name();
      else if(SRP_Identifier* srp = dynamic_cast<SRP_Identifier*>(extn))
         requested_srp_id = srp->identifier();
      else if(Renegotation_Extension* reneg = dynamic_cast<Renegotation_Extension*>(extn))
         {
         // checked by TLS_Client / TLS_Server as they know the handshake state
         has_secure_renegotiation = true;
         renegotiation_info_bits = reneg->renegotiation_info();
         }
      }
   }

/*
* Check if we offered this ciphersuite
*/
bool Client_Hello::offered_suite(u16bit ciphersuite) const
   {
   for(size_t i = 0; i != suites.size(); ++i)
      if(suites[i] == ciphersuite)
         return true;
   return false;
   }

/*
* Create a new Server Hello message
*/
Server_Hello::Server_Hello(Record_Writer& writer,
                           TLS_Handshake_Hash& hash,
                           const TLS_Policy& policy,
                           RandomNumberGenerator& rng,
                           const std::vector<X509_Certificate>& certs,
                           const Client_Hello& c_hello,
                           const MemoryRegion<byte>& session_id,
                           Version_Code ver) :
   s_version(ver),
   sess_id(session_id),
   s_random(rng.random_vec(32))
   {
   bool have_rsa = false, have_dsa = false;

   for(size_t i = 0; i != certs.size(); ++i)
      {
      Public_Key* key = certs[i].subject_public_key();
      if(key->algo_name() == "RSA")
         have_rsa = true;

      if(key->algo_name() == "DSA")
         have_dsa = true;
      }

   suite = policy.choose_suite(c_hello.ciphersuites(), have_rsa, have_dsa);

   if(suite == 0)
      throw TLS_Exception(HANDSHAKE_FAILURE,
                          "Can't agree on a ciphersuite with client");

   comp_method = policy.choose_compression(c_hello.compression_methods());

   send(writer, hash);
   }

/*
* Create a new Server Hello message
*/
Server_Hello::Server_Hello(Record_Writer& writer,
                           TLS_Handshake_Hash& hash,
                           RandomNumberGenerator& rng,
                           const MemoryRegion<byte>& session_id,
                           u16bit ciphersuite,
                           byte compression,
                           Version_Code ver) :
   s_version(ver),
   sess_id(session_id),
   s_random(rng.random_vec(32)),
   suite(ciphersuite),
   comp_method(compression)
   {
   send(writer, hash);
   }

/*
* Serialize a Server Hello message
*/
MemoryVector<byte> Server_Hello::serialize() const
   {
   MemoryVector<byte> buf;

   buf.push_back(static_cast<byte>(s_version >> 8));
   buf.push_back(static_cast<byte>(s_version     ));
   buf += s_random;

   append_tls_length_value(buf, sess_id, 1);

   buf.push_back(get_byte(0, suite));
   buf.push_back(get_byte(1, suite));

   buf.push_back(comp_method);

   return buf;
   }

/*
* Deserialize a Server Hello message
*/
void Server_Hello::deserialize(const MemoryRegion<byte>& buf)
   {
   if(buf.size() < 38)
      throw Decoding_Error("Server_Hello: Packet corrupted");

   TLS_Data_Reader reader(buf);

   s_version = static_cast<Version_Code>(reader.get_u16bit());

   if(s_version != SSL_V3 && s_version != TLS_V10 && s_version != TLS_V11)
      {
      throw TLS_Exception(PROTOCOL_VERSION,
                          "Server_Hello: Unsupported server version");
      }

   s_random = reader.get_fixed<byte>(32);

   sess_id = reader.get_range<byte>(1, 0, 32);

   suite = reader.get_u16bit();

   comp_method = reader.get_byte();

   TLS_Extensions extensions(reader);

   for(size_t i = 0; i != extensions.count(); ++i)
      {
      TLS_Extension* extn = extensions.at(i);

      if(Renegotation_Extension* reneg = dynamic_cast<Renegotation_Extension*>(extn))
         {
         // checked by TLS_Client / TLS_Server as they know the handshake state
         has_secure_renegotiation = true;
         renegotiation_info_bits = reneg->renegotiation_info();
         }
      }
   }

/*
* Create a new Server Hello Done message
*/
Server_Hello_Done::Server_Hello_Done(Record_Writer& writer,
                                     TLS_Handshake_Hash& hash)
   {
   send(writer, hash);
   }

/*
* Serialize a Server Hello Done message
*/
MemoryVector<byte> Server_Hello_Done::serialize() const
   {
   return MemoryVector<byte>();
   }

/*
* Deserialize a Server Hello Done message
*/
void Server_Hello_Done::deserialize(const MemoryRegion<byte>& buf)
   {
   if(buf.size())
      throw Decoding_Error("Server_Hello_Done: Must be empty, and is not");
   }

}
