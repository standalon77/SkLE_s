/*
 * Socket.h
 *
 *  Created on: Jun 18, 2019
 *      Author: firstuser
 */

#ifndef SOCKET_H_
#define SOCKET_H_


#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string>
#include <arpa/inet.h>

const int MOD_SIZE = 1024;						// (check) bit
const int KEY_SIZE = MOD_SIZE/8;				// byte: N
const int ENC_SIZE = KEY_SIZE*2;				// byte: N^2
const int DATA_NUMBER_LENGTH = 5;				// (check) l_2 : data 갯수의 비트수 (실제 데이터 길이)
const int GMP_N_SIZE = MOD_SIZE/64;
const int HED_SIZE = 5;
const int HED_LEN  = 3;
const int NUM_PPkNN_THREAD = 8;					// (check)

const int MAXHOSTNAME = 200;
const int MAXCONNECTIONS = 5;
//const int MAXRECV = 500;
const int MAXRECV = ENC_SIZE*DATA_NUMBER_LENGTH+50;

class Socket
{
 public:
  Socket();
  virtual ~Socket();

  // Server initialization
  bool create();
  bool bind ( const int port );
  bool listen() const;
  bool accept ( Socket& ) const;

  // Client initialization
  bool connect ( const std::string host, const int port );

  // Data Transimission
  bool send ( const std::string ) const;
  bool send ( const void* s, const size_t size_s ) const;
  int recv ( std::string& ) const;
  int recv ( void* s, const size_t size_s ) const;


  void set_non_blocking ( const bool );

  bool is_valid() const { return m_sock != -1; }

 private:

  int m_sock;
  sockaddr_in m_addr;

};

#endif /* SOCKET_H_ */
