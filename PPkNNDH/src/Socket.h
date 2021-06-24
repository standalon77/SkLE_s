// Definition of the Socket class

#ifndef Socket_class
#define Socket_class

//------------------------------------------------------------------------
//// Test Data (n=20)
//const int DATA_SQUARE_LENGTH = 11;				// (check) l_1 : data 제곱의 비트수 (실제 데이터 길이)
//const int DATA_NUMBER_LENGTH = 5;				// (check) l_2 : data 갯수의 비트수 (실제 데이터 길이)
//
//const int DATA_NUM = 20;						// (check)e
//const int DATA_DIMN = 4;							// (check)
//const int CLASS_SIZE= 4;							// (check)
//------------------------------------------------------------------------
//// Car Evaluation (n=1728)
//const int DATA_SQUARE_LENGTH = 7;				// (check) l_1 : data 제곱의 비트수 (실제 데이터 길이)
//const int DATA_NUMBER_LENGTH = 11;				// (check) l_2 : data 갯수의 비트수 (실제 데이터 길이)
//
//const int DATA_NUM = 1728;						// (check)e
//const int DATA_DIMN = 6;							// (check)
//const int CLASS_SIZE= 4;							// (check)
//------------------------------------------------------------------------
//// Mushroom (n=8124)
//const int DATA_SQUARE_LENGTH = 9;				// (check) l_1 : data 제곱의 비트수 (실제 데이터 길이)
//const int DATA_NUMBER_LENGTH = 13;				// (check) l_2 : data 갯수의 비트수 (실제 데이터 길이)
//
//const int DATA_NUM = 8124;						// (check)e
//const int DATA_DIMN = 22;							// (check)
//const int CLASS_SIZE= 2;							// (check)
//------------------------------------------------------------------------



//const int DATA_SQUARE_LENGTH = 12;			// (check) l_1 : data 제곱의 비트수 (실제 데이터 길이)
//const int DATA_NUMBER_LENGTH = 5;			// (check) l_2 : data 갯수의 비트수 (실제 데이터 길이)
#define DATA_SQUARE_LENGTH 9					// (check) l_1 : data 제곱의 비트수 (실제 데이터 길이)
#define DATA_NUMBER_LENGTH 13					// (check) l_2 : data 갯수의 비트수 (실제 데이터 길이)
//#define CLAS_NUMBER_LENGTH 4					// (check) l_2 : data 갯수의 비트수 (실제 데이터 길이)
const int MOD_SIZE = 1024;						// (check) bit
const int KEY_SIZE = MOD_SIZE/8;				// byte: N
const int ENC_SIZE = KEY_SIZE*2;				// byte: N^2
const int GMP_N_SIZE = MOD_SIZE/64;
const int HED_SIZE = 5;
const int HED_LEN  = 3;

const int DATA_NUM = 8124;							// (check)e
const int DATA_DIMN = 22;							// (check)
const int CLASS_SIZE= 2;							// (check)		CLAS_NUMBER_LENGTH
const int PARAM_K =  1000;							// (check)

const int THREAD1_NUM  = 8;					// (check) Main thread의 개수.
const int THREAD2_NUM = THREAD1_NUM >= CLASS_SIZE ? CLASS_SIZE : THREAD1_NUM;	// Class thread의 개수. (SBD, SkLE_s for f_j)
// 각 thread가 처리하는 데이터의 갯수, (problem) 데이터의 갯수가 정확히 나누어지지 않는 경우 일부 thread는 메모리 낭비가 있을수 있다. (struct로 미리 선언하기 위해 불가피하게 정의함.)
const int THREAD_DATA_NUM = DATA_NUM%THREAD1_NUM==0 ? DATA_NUM/THREAD1_NUM : (int)(DATA_NUM/THREAD1_NUM)+1;

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <unistd.h>
#include <string>
#include <arpa/inet.h>

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


#endif
