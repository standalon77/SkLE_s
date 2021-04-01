/*
 * PaillierCrypto.h
 *
 *  Created on: Jun 18, 2019
 *      Author: PJS
 */

#ifndef PAILLIERCRYPTO_H_
#define PAILLIERCRYPTO_H_

#define _DEBUG_INIT_1
//#define _DEBUG_Assert
#define _DEBUG_THREAD
//#define _DEBUG_Initialization
//#define _DEBUG_SquaredSimilarity
//#define _DEBUG_SecureMultiplication
//#define _DEBUG_SecureBitDecomposition
//#define _DEBUG_EncryptedLSB
//#define _DEBUG_SVR
#define _DEBUG_SCI
//#define _DEBUG_SCF
//#define _DEBUG_TERMINATE_PGM
//#define _DEBUG_Communication

#include <iostream>
#include <string>
#include <gmp.h>
extern "C"{
	#include "paillier.h"
}
#include "ClientSocket.h"
#include <assert.h>
#include <queue>
#include <mutex>
#include <condition_variable>

//const int MOD_SIZE = 1024;						// (check) bit
//const int KEY_SIZE = MOD_SIZE/8;				// byte: N
//const int ENC_SIZE = KEY_SIZE*2;				// byte: N^2
//const int DATA_NUMBER_LENGTH = 5;				// (check) l_2 : data 갯수의 비트수 (실제 데이터 길이)
//const int GMP_N_SIZE = MOD_SIZE/64;
//const int HED_SIZE = 5;
//const int HED_LEN  = 3;
//const int NUM_PPkNN_THREAD = 4;					// (check)

// Command Tag
const unsigned char COM_MUL1 	= 0x01;
const unsigned char COM_MUL2 	= 0x02;
const unsigned char COM_LSB 	= 0x03;
const unsigned char COM_SVR 	= 0x04;
const unsigned char COM_SCI 	= 0x05;
const unsigned char COM_SZP 	= 0x06;
const unsigned char COM_SCF 	= 0x07;
const unsigned char COM_TERM 	= 0xFF;

// send, recv를 관리하기 위한 struct
typedef struct {
	std::queue<unsigned char*> q;
	std::mutex m;
	std::condition_variable cv;
} th_t;

class PaillierCrypto {
private:
	ClientSocket *mCSocket;
	paillier_pubkey_t* mPubKey;
	paillier_prvkey_t* mPrvKey;
	paillier_plaintext_t  pN12;

	inline void paillier_ciphertext_from_bytes(paillier_ciphertext_t* ct, void* c, int len );
	inline void paillier_ciphertext_to_bytes(unsigned char* buf, int len, paillier_ciphertext_t* ct );
	inline void SetSendMsg(unsigned char* ucSendPtr, const unsigned char* ucRecvPtr, unsigned char* Data, const unsigned short Len);
	inline void SetSendMsg(unsigned char* ucSendPtr, const unsigned char* ucRecvPtr, unsigned char bData);
	inline unsigned short Byte2Short(unsigned char* In);
	inline void DebugOut(const mpz_t pData);
	inline void DebugOut(const char* pMsg, const mpz_t pData);
	inline void DebugOut(const char* pMsg, const mpz_t pData, 			const short idx, const short DHidx);
	inline void DebugOut(const char* pMsg, const unsigned char* pData);
	inline void DebugOut(const char* pMsg, const unsigned char* pData,	const short idx, const short DHidx);
	inline void DebugOut(const char* pMsg, short pData, 					const short idx, const short DHidx);
	inline void DebugDec(paillier_ciphertext_t* cTxt);
	inline void DebugDec(const char* pMsg, paillier_ciphertext_t* cTxt);
	inline void DebugDec(const char* pMsg, paillier_ciphertext_t* cTxt, const short idx, const short DHidx);
	inline void DebugCom(const char* pMsg, const unsigned char *data, int len);
	inline void DebugCom(const char* pMsg, unsigned char *data, int len, const short idx, const short DHidx);

public:
	PaillierCrypto();
	PaillierCrypto(int pModSize);
	virtual ~PaillierCrypto();
	bool distributePubKey();
	bool distributePrvKey();			// for debugging

//	bool SecMul1	 (unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, th_t* tSend);
//	bool SecMul2	 (unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, th_t* tSend);
//	void EncryptedLSB(unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, th_t* tSend);
//	void SVR		 (unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, th_t* tSend);
//	int  Comparison  (unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, th_t* tSend);
//	bool SCF		 (unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, th_t* tSend);
//	void TerminatePgm(unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, th_t* tSend);

	bool SecMul1	 	(unsigned short idx, unsigned char* ucRecvPtr);
	bool SecMul2	 	(unsigned short idx, unsigned char* ucRecvPtr);
	void EncryptedLSB	(unsigned short idx, unsigned char* ucRecvPtr);
	void SVR		 	(unsigned short idx, unsigned char* ucRecvPtr);
	int  SCI			(unsigned short idx, unsigned char* ucRecvPtr);
	bool SCF		 	(unsigned short idx, unsigned char* ucRecvPtr);
	void TerminatePgm	(unsigned short idx, unsigned char* ucRecvPtr);

//	int Sender(th_t* tSend);
	int Receiver(th_t* tRecv);
	void DebugComMain(const char* pMsg, unsigned char *data, int len, const short idx, const short DHidx);
};

#endif /* PAILLIERCRYPTO_H_ */
