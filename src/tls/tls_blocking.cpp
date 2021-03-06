/*
* TLS Blocking API
* (C) 2013 Jack Lloyd
*
* Released under the terms of the Botan license
*/

#include <botan/tls_blocking.h>

namespace Botan {

namespace TLS {

using namespace std::placeholders;

Blocking_Client::Blocking_Client(std::function<size_t (byte[], size_t)> read_fn,
                                 std::function<void (const byte[], size_t)> write_fn,
                                 Session_Manager& session_manager,
                                 Credentials_Manager& creds,
                                 const Policy& policy,
                                 RandomNumberGenerator& rng,
                                 const Server_Information& server_info,
                                 const Protocol_Version offer_version,
                                 std::function<std::string (std::vector<std::string>)> next_protocol) :
   m_read_fn(read_fn),
   m_channel(write_fn,
             std::bind(&Blocking_Client::process_data, this, _1, _2, _3),
             std::bind(&Blocking_Client::handshake_complete, this, _1),
             session_manager,
             creds,
             policy,
             rng,
             server_info,
             offer_version,
             next_protocol)
   {
   }

bool Blocking_Client::handshake_complete_cb(const Session& session)
   {
   return this->handshake_complete(session);
   }

void Blocking_Client::process_data(const byte data[], size_t data_len,
                                   const Alert& alert)
   {
   m_plaintext.insert(m_plaintext.end(), data, data + data_len);

   if(alert.is_valid())
      alert_notification(alert);
   }

void Blocking_Client::do_handshake()
   {
   std::vector<byte> readbuf(4096);

   while(!m_channel.is_closed() && !m_channel.is_active())
      {
      const size_t from_socket = m_read_fn(&readbuf[0], readbuf.size());
      m_channel.received_data(&readbuf[0], from_socket);
      }
   }

size_t Blocking_Client::read(byte buf[], size_t buf_len)
   {
   std::vector<byte> readbuf(4096);

   while(m_plaintext.empty() && !m_channel.is_closed())
      {
      const size_t from_socket = m_read_fn(&readbuf[0], readbuf.size());
      m_channel.received_data(&readbuf[0], from_socket);
      }

   const size_t returned = std::min(buf_len, m_plaintext.size());

   for(size_t i = 0; i != returned; ++i)
      buf[i] = m_plaintext[i];
   m_plaintext.erase(m_plaintext.begin(), m_plaintext.begin() + returned);

   BOTAN_ASSERT_IMPLICATION(returned == 0, m_channel.is_closed(),
                            "Only return zero if channel is closed");

   return returned;
   }

}

}
