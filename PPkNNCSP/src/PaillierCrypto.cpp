/*
 * PaillierCrypto.cpp
 *
 *  Created on: Jun 18, 2019
 *      Author: PJS
 */


#include "PaillierCrypto.h"
#include <iostream>
#include <string.h>
#include "SocketException.h"
#include <cstring>

PaillierCrypto::PaillierCrypto(): mCSocket(NULL), mPubKey(NULL), mPrvKey(NULL) {}

PaillierCrypto::PaillierCrypto(int pModSize)
{
    // Generate public and secret keys
    paillier_keygen(pModSize, &mPubKey, &mPrvKey, paillier_get_rand_devurandom);

	#ifdef _DEBUG_Initialization
    gmp_printf("[CSP] Public key(n)\t\t: %ZX\n", mPubKey->n);
    gmp_printf("[CSP] Private key(lambda)\t: %ZX\n", mPrvKey->lambda);
	#endif

	try {
//		mCSocket = new ClientSocket("192.168.0.9", 3000);
		mCSocket = new ClientSocket("localhost", 3000);
	}
	catch ( SocketException& e ) {
		std::cout << "Exception: " << e.description() << std::endl;
	}

	// (N-1)/2
	#ifdef _DEBUG_INIT_1
	mpz_init(pN12.m);
	#else
	mpz_init2(pN12.m, GMP_N_SIZE+1);
	#endif
	mpz_sub_ui(pN12.m, mPubKey->n, 1);
	mpz_fdiv_q_2exp(pN12.m, pN12.m, 1);

	#ifdef _DEBUG_Assert
	assert(pN12.m->_mp_alloc ==GMP_N_SIZE+1);
	#endif

	return;
}

PaillierCrypto::~PaillierCrypto()
{
	paillier_freepubkey(mPubKey);
	paillier_freeprvkey(mPrvKey);
	delete(mCSocket);
}

bool PaillierCrypto::distributePubKey()
{
	// distribute public key
	char* cpPubKey = paillier_pubkey_to_hex(mPubKey);
	#ifdef _DEBUG_Initialization
    std::cout << "[CSP] Public Key (Hex)\t\t: " << cpPubKey << std::endl;
	#endif

	try {
		mCSocket->send(cpPubKey, KEY_SIZE*2);		// string으로 전송
	}
	catch ( SocketException& e ) {
		std::cout << "Exception: " << e.description() << std::endl;
	}

	delete[] cpPubKey;

	return true;
}

// for debugging
bool PaillierCrypto::distributePrvKey()
{
	// distribute private key
	char* cpPrvKey = paillier_prvkey_to_hex(mPrvKey);
	#ifdef _DEBUG_Initialization
    std::cout << "[CSP] Private Key (Hex)\t\t: " << cpPrvKey << std::endl;
	#endif

	try {
		mCSocket->send(cpPrvKey, KEY_SIZE*2);		// string으로 전송
	}
	catch ( SocketException& e ) {
		std::cout << "Exception: " << e.description() << std::endl;
	}

	delete[] cpPrvKey;

	return true;
}

//bool PaillierCrypto::SecMul1(unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, th_t* tSend)
bool PaillierCrypto::SecMul1(unsigned short idx, unsigned char* ucRecvPtr)
{
	paillier_ciphertext_t cEh, cEa;
	paillier_plaintext_t  pHa, pH;

	#ifdef _DEBUG_INIT_1
	mpz_inits(cEh.c, cEa.c, pHa.m, pH.m, NULL);
	#else
	mpz_init2(cEh.c, 2*GMP_N_SIZE*2);
	mpz_init2(cEa.c, 2*GMP_N_SIZE);
	mpz_init2(pHa.m, 2*GMP_N_SIZE+1);
	mpz_init2(pH.m, 2*GMP_N_SIZE);
	#endif

	unsigned char bEh[ENC_SIZE]={0,};
	unsigned char ucSendPtr[HED_SIZE+ENC_SIZE]={0,};
	short sLen, sDHidx;

	sDHidx = Byte2Short(ucRecvPtr);
	sLen = Byte2Short(ucRecvPtr+HED_LEN);
	#ifdef _DEBUG_SecureMultiplication
	DebugCom("Encrypted a' (Hex)\t\t\t", ucRecvPtr, sLen+HED_SIZE, idx, sDHidx);
	#endif

	#ifdef _DEBUG_Assert
	assert(sLen == ENC_SIZE);
	#endif

	// a' = E(a+r_a)
	paillier_ciphertext_from_bytes(&cEa, ucRecvPtr+HED_SIZE, ENC_SIZE);
	#ifdef _DEBUG_SecureMultiplication
	DebugOut("Encrypted a' (Copied)\t\t\t", cEa.c, idx, sDHidx);
	#endif

	// h_a = D(a')
	paillier_dec(&pHa, mPubKey, mPrvKey, &cEa);
	#ifdef _DEBUG_SecureMultiplication
    DebugOut("Decrypted ha\t\t\t", pHa.m, idx, sDHidx);
	#endif

    // h = h_a^2 mod N
    mpz_mul(pH.m, pHa.m, pHa.m);
    mpz_mod(pH.m, pH.m, mPubKey->n);
	#ifdef _DEBUG_SecureMultiplication
    DebugOut("h = ha^2 mod N\t\t\t", pH.m, idx, sDHidx);
	#endif

    // h' = E(h)
	paillier_enc(&cEh, mPubKey, &pH, paillier_get_rand_devurandom);
	#ifdef _DEBUG_SecureMultiplication
    DebugOut("h' = E(h)\t\t\t", cEh.c, idx, sDHidx);
	#endif

    // send h'
	paillier_ciphertext_to_bytes(bEh, ENC_SIZE, &cEh);
	#ifdef _DEBUG_SecureMultiplication
    DebugCom("h' = E(h) (Hex)\t\t\t", bEh, ENC_SIZE, idx, sDHidx);
	#endif

    sLen = ENC_SIZE;
	SetSendMsg(ucSendPtr, ucRecvPtr, bEh, sLen);
    sLen += HED_SIZE;
	#ifdef _DEBUG_SecureMultiplication
    DebugCom("h' = E(h) (copied)\t\t\t", ucSendPtr, sLen, idx, sDHidx);
	#endif

//	mSendMtx->lock();
//	mSendQueue->push(ucSendPtr);
//	mSendMtx->unlock();
//	mSendCV->notify_all();			// Communication thread가 아니라 PPkNN thread가 notify되는 것은 아닌지?

	try {
		mCSocket->send(ucSendPtr, sLen);
	}
	catch ( SocketException& e ) {
		std::cout << "Exception: " << e.description() << std::endl;
	}

	// checking the allocated size  of GMP
	#ifdef _DEBUG_Assert
	assert(pHa.m->_mp_alloc == 2*GMP_N_SIZE+1);
	assert( pH.m->_mp_alloc == 2*GMP_N_SIZE);
	assert(cEh.c->_mp_alloc == 2*GMP_N_SIZE*2);
	assert(cEa.c->_mp_alloc == 2*GMP_N_SIZE);
	#endif

	memset(ucRecvPtr, 0, HED_SIZE+2*ENC_SIZE);
	ucRecvPtr[1] = 0xff;

	return true;
}

//bool PaillierCrypto::SecMul2(unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, th_t* tSend)
bool PaillierCrypto::SecMul2(unsigned short idx, unsigned char* ucRecvPtr)
{
	paillier_ciphertext_t cEh, cEa, cEb;
	paillier_plaintext_t  pHa, pHb, pH;

	#ifdef _DEBUG_INIT_1
	mpz_inits(cEh.c, cEa.c, cEb.c, pHa.m, pHb.m, pH.m, NULL);
	#else
	mpz_init2(cEh.c, 2*GMP_N_SIZE*2);
	mpz_init2(cEa.c, 2*GMP_N_SIZE);
	mpz_init2(cEb.c, 2*GMP_N_SIZE);
	mpz_init2(pHa.m, 2*GMP_N_SIZE+1);
	mpz_init2(pHb.m, 2*GMP_N_SIZE+1);
	mpz_init2(pH.m, 2*GMP_N_SIZE);
	#endif

	unsigned char bEh[ENC_SIZE]={0, };
	unsigned char ucSendPtr[HED_SIZE+ENC_SIZE]={0,};
	short sLen, sDHidx;

	sDHidx = Byte2Short(ucRecvPtr);
	sLen = Byte2Short(ucRecvPtr+HED_LEN);
	#ifdef _DEBUG_SecureMultiplication
	DebugCom("Encrypted a' and b' (Hex)\t\t", ucRecvPtr, sLen+HED_SIZE, idx, sDHidx);
	#endif

	#ifdef _DEBUG_Assert
	assert(sLen == 2*ENC_SIZE);
	#endif

	// a' = E(a+r_a)
	paillier_ciphertext_from_bytes(&cEa, ucRecvPtr+HED_SIZE, ENC_SIZE);
	#ifdef _DEBUG_SecureMultiplication
	DebugOut("Encrypted a' (Copied)\t\t", cEa.c, idx, sDHidx);
	#endif

	// b' = E(b+r_b)
	paillier_ciphertext_from_bytes(&cEb, ucRecvPtr+HED_SIZE+ENC_SIZE, ENC_SIZE);
	#ifdef _DEBUG_SecureMultiplication
	DebugOut("Encrypted b' (Copied)\t\t", cEb.c, idx, sDHidx);
	#endif

	// h_a = D(a'), h_b = D(b')
	paillier_dec(&pHa, mPubKey, mPrvKey, &cEa);
	#ifdef _DEBUG_SecureMultiplication
    DebugOut("Decrypted ha\t\t\t", pHa.m, idx, sDHidx);
	#endif

    paillier_dec(&pHb, mPubKey, mPrvKey, &cEb);
    #ifdef _DEBUG_SecureMultiplication
    DebugOut("Decrypted hb\t\t\t", pHb.m, idx, sDHidx);
	#endif

    // h = h_a * h_b  mod N
    mpz_mul(pH.m, pHa.m, pHb.m);
    mpz_mod(pH.m, pH.m, mPubKey->n);
	#ifdef _DEBUG_SecureMultiplication
    DebugOut("h = ha * hb mod N\t\t\t", pH.m, idx, sDHidx);
	#endif

    // h' = E(h)
	paillier_enc(&cEh, mPubKey, &pH, paillier_get_rand_devurandom);
	#ifdef _DEBUG_SecureMultiplication
    DebugOut("h' = E(h)\t\t\t\t", cEh.c, idx, sDHidx);
	#endif

    // send h'
	paillier_ciphertext_to_bytes(bEh, ENC_SIZE, &cEh);
	#ifdef _DEBUG_SecureMultiplication
    DebugCom("h' = E(h) (Hex)\t\t\t", bEh, ENC_SIZE, idx, sDHidx);
	#endif

    sLen = ENC_SIZE;
	SetSendMsg(ucSendPtr, ucRecvPtr, bEh, sLen);
    sLen += HED_SIZE;
	#ifdef _DEBUG_SecureMultiplication
    DebugCom("h' = E(h) (copied)\t\t", ucSendPtr, sLen, idx, sDHidx);
	#endif

//	mSendMtx->lock();
//	mSendQueue->push(ucSendPtr);
//	mSendMtx->unlock();
//	mSendCV->notify_all();			// Communication thread가 아니라 PPkNN thread가 notify되는 것은 아닌지?

	try {
		mCSocket->send(ucSendPtr, sLen);
	}
	catch ( SocketException& e ) {
		std::cout << "Exception: " << e.description() << std::endl;
	}

	// checking the allocated size  of GMP
	#ifdef _DEBUG_Assert
	assert(pHa.m->_mp_alloc == 2*GMP_N_SIZE+1);
	assert(pHb.m->_mp_alloc == 2*GMP_N_SIZE+1);
	assert( pH.m->_mp_alloc == 2*GMP_N_SIZE);
	assert(cEh.c->_mp_alloc == 2*GMP_N_SIZE*2);
	assert(cEa.c->_mp_alloc == 2*GMP_N_SIZE);
	assert(cEb.c->_mp_alloc == 2*GMP_N_SIZE);
	#endif

	memset(ucRecvPtr, 0, HED_SIZE+2*ENC_SIZE);
	ucRecvPtr[1] = 0xff;

	return true;
}

//void PaillierCrypto::EncryptedLSB(unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, lsb_t* tLsb, th_t* tSend)
void PaillierCrypto::EncryptedLSB(unsigned short idx, unsigned char* ucRecvPtr)
{
	paillier_plaintext_t pY, p;
	paillier_ciphertext_t c, cY;

	#ifdef _DEBUG_INIT_1
	mpz_inits(pY.m, p.m, c.c, cY.c, NULL);
	#else
	mpz_init2(pY.m, 2*GMP_N_SIZE+1);
	mpz_init2(p.m, 1);
	mpz_init2(c.c, 3*GMP_N_SIZE);
	mpz_init2(cY.c, 2*GMP_N_SIZE);
	#endif

	int iEven;
	unsigned char bAlpha[ENC_SIZE] = {0, };
	unsigned char ucSendPtr[HED_SIZE+ENC_SIZE] = {0, };
	short sLen, sDHidx;

	// Y = E(x+r)
	sDHidx = Byte2Short(ucRecvPtr);
	sLen = Byte2Short(ucRecvPtr+HED_LEN);
	#ifdef _DEBUG_EncryptedLSB
    DebugCom("Y = E(x+r) (Hex)\t\t\t", ucRecvPtr, sLen+HED_SIZE, idx, sDHidx);
	#endif

	#ifdef _DEBUG_Assert
	assert(sLen == ENC_SIZE);
	#endif

	paillier_ciphertext_from_bytes(&cY, ucRecvPtr+HED_SIZE, ENC_SIZE);
	#ifdef _DEBUG_EncryptedLSB
	DebugOut("Y = E(x+r) (Copied)\t\t", cY.c, idx, sDHidx);
	#endif

	// y = D(Y) = x+r
	paillier_dec(&pY, mPubKey, mPrvKey, &cY);
	#ifdef _DEBUG_EncryptedLSB
    DebugOut("Decrypted y = x+r\t\t\t", pY.m, idx, sDHidx);
	#endif

	// determine whether random y is even
	iEven = mpz_even_p(pY.m);
	#ifdef _DEBUG_EncryptedLSB
    DebugOut("y is even?\t\t\t", iEven, idx, sDHidx);
	#endif

    // send alpha = E(0) or E(1)
	if (iEven) {
		mpz_set_ui(p.m, 0);
		paillier_enc(&c, mPubKey, &p, paillier_get_rand_devurandom);
		paillier_ciphertext_to_bytes(bAlpha, ENC_SIZE, &c);
		#ifdef _DEBUG_EncryptedLSB
	    DebugCom("(y:even) alpha = E(0) (Hex)\t", bAlpha, ENC_SIZE, idx, sDHidx);
		#endif
	}
	else {
		mpz_set_ui(p.m, 1);				//?? 앞과 동일
		paillier_enc(&c, mPubKey, &p, paillier_get_rand_devurandom);
		paillier_ciphertext_to_bytes(bAlpha, ENC_SIZE, &c);
		#ifdef _DEBUG_EncryptedLSB
	    DebugCom("(y:odd) alpha = E(1) (Hex)\t", bAlpha, ENC_SIZE, idx, sDHidx);	//?? 앞과 동일
		#endif
	}

    sLen = ENC_SIZE;
	SetSendMsg(ucSendPtr, ucRecvPtr, bAlpha, sLen);
    sLen += HED_SIZE;
	#ifdef _DEBUG_SecureMultiplication
    DebugCom("h' = E(h) (copied)\t\t", ucSendPtr, sLen, idx, sDHidx);
	#endif

//	mSendMtx->lock();
//	mSendQueue->push(ucSendPtr);
//	mSendMtx->unlock();
//	mSendCV->notify_all();			// Communication thread가 아니라 PPkNN thread가 notify되는 것은 아닌지?

	try {
		mCSocket->send(ucSendPtr, sLen);
	}
	catch ( SocketException& e ) {
		std::cout << "Exception: " << e.description() << std::endl;
	}

	#ifdef _DEBUG_Assert
	// checking the allocated size  of GMP
	assert(pY.m->_mp_alloc == 2*GMP_N_SIZE+1);
	assert( p.m->_mp_alloc == 1);
	assert( c.c->_mp_alloc <= 3*GMP_N_SIZE);
	assert(cY.c->_mp_alloc == 2*GMP_N_SIZE);
	#endif

	memset(ucRecvPtr, 0, HED_SIZE+2*ENC_SIZE);
	ucRecvPtr[1] = 0xff;

	return;
}

//void PaillierCrypto::SVR(unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, th_t* tSend)
void PaillierCrypto::SVR(unsigned short idx, unsigned char* ucRecvPtr)
{
	paillier_plaintext_t pW;
	paillier_ciphertext_t cW;

	#ifdef _DEBUG_INIT_1
	mpz_inits(pW.m, cW.c, NULL);
	#else
	mpz_init2(pW.m, GMP_N_SIZE);
	mpz_init2(cW.c, 2*GMP_N_SIZE);
	#endif

	unsigned char ucSendPtr[HED_SIZE+1];
	int iZero;
	char bGamma;
	short sLen, sDHidx;

	// W
	sDHidx = Byte2Short(ucRecvPtr);
	sLen = Byte2Short(ucRecvPtr+HED_LEN);
	#ifdef _DEBUG_SVR
    DebugCom("W (Hex)\t\t\t\t", ucRecvPtr, sLen+HED_SIZE, idx, sDHidx);
	#endif

	#ifdef _DEBUG_Assert
	assert(sLen == ENC_SIZE);
	#endif

	paillier_ciphertext_from_bytes(&cW, ucRecvPtr+HED_SIZE, ENC_SIZE);
	#ifdef _DEBUG_SVR
	DebugOut("W (Copied)\t\t\t", cW.c, idx, sDHidx);
	#endif

	// w = D(W)
	paillier_dec(&pW, mPubKey, mPrvKey, &cW);
	#ifdef _DEBUG_SVR
    DebugOut("Decrypted w\t\t\t", pW.m, idx, sDHidx);
	#endif

    // send gamma (result)
    iZero = mpz_cmp_ui(pW.m, 0);
    if (iZero==0)  	{ bGamma = 1; }		// Success
    else	    	{ bGamma = 0; }		// Fail

	SetSendMsg(ucSendPtr, ucRecvPtr, bGamma);
    sLen = HED_SIZE+1;
	#ifdef _DEBUG_SVR
	DebugCom("Gamma (copied)\t\t\t", ucSendPtr, sLen, idx, sDHidx);
	#endif

//	mSendMtx->lock();
//	mSendQueue->push(ucSendPtr);
//	mSendMtx->unlock();
//	mSendCV->notify_all();			// Communication thread가 아니라 PPkNN thread가 notify되는 것은 아닌지?

	try {
		mCSocket->send(ucSendPtr, sLen);
	}
	catch ( SocketException& e ) {
		std::cout << "Exception: " << e.description() << std::endl;
	}

	#ifdef _DEBUG_Assert
	// checking the allocated size  of GMP
	assert(pW.m->_mp_alloc ==   GMP_N_SIZE);
	assert(cW.c->_mp_alloc == 2*GMP_N_SIZE);
	#endif

	memset(ucRecvPtr, 0, HED_SIZE+2*ENC_SIZE);
	ucRecvPtr[1] = 0xff;

	return;
}


int PaillierCrypto::SCI(unsigned short idx, unsigned char* ucRecvPtr)
{
	paillier_plaintext_t  pV, pT;
	paillier_ciphertext_t cV, cB;

	#ifdef _DEBUG_INIT_1
	mpz_inits(pV.m, pT.m, cV.c, cB.c, cB.c, NULL);
	#else
	mpz_init2(pV.m, 2*GMP_N_SIZE+1);
	mpz_init2(pT.m, 1);
	mpz_init2(cV.c, 2*GMP_N_SIZE);
	mpz_init2(cB.c, 2*GMP_N_SIZE);
	#endif

	unsigned char bB[ENC_SIZE] = {0, };
	unsigned char ucSendPtr[HED_SIZE+ENC_SIZE*DATA_NUMBER_LENGTH] = {0, };				//?? HED_SIZE+1만큼 전송할때 문제가 되지 않는지?
	int iZero=0;
	short sLen, sDHidx;

   sDHidx = Byte2Short(ucRecvPtr);
	sLen = Byte2Short(ucRecvPtr+HED_LEN);
	#ifdef _DEBUG_SCI
	DebugCom("V' (Hex)\t\t\t\t", ucRecvPtr, sLen+HED_SIZE, idx, sDHidx);
	#endif

	#ifdef _DEBUG_Assert
	assert(sLen == ENC_SIZE*DATA_NUMBER_LENGTH);
	#endif


	for (int i=0 ; i<DATA_NUMBER_LENGTH ; i++) {
		// cV
		paillier_ciphertext_from_bytes(&cV, ucRecvPtr+HED_SIZE+i*DATA_NUMBER_LENGTH, ENC_SIZE);
		#ifdef _DEBUG_SCI
		DebugOut("Encrypted cV (Copied)\t\t", cV.c, idx, sDHidx);
		#endif

		// cV = D(cV')
		paillier_dec(&pV, mPubKey, mPrvKey, &cV);
		#ifdef _DEBUG_SCI
		DebugOut("Decrypted cV\t\t\t", pV.m, idx, sDHidx);
		#endif

		// compare with 0, (N-1)/2, N
		if (mpz_cmp_d(pV.m, 0) == 0)
			iZero++;
	}

	if (iZero > 0) 		mpz_set_ui(pT.m, 0);
	else 					mpz_set_ui(pT.m, 1);

	paillier_enc(&cB, mPubKey, &pT, paillier_get_rand_devurandom);
	#ifdef _DEBUG_SCI
	DebugDec("Beta'=E(0) or E(1)\t\t", &cB, idx, sDHidx);
	#endif

    paillier_ciphertext_to_bytes(bB, ENC_SIZE, &cB);
	#ifdef _DEBUG_SCI
	DebugCom("Beta'=E(0) or E(1) (Hex)\t\t", bB, ENC_SIZE, idx, sDHidx);
	#endif

    sLen = ENC_SIZE;
	SetSendMsg(ucSendPtr, ucRecvPtr, bB, sLen);
    sLen += HED_SIZE;
	#ifdef _DEBUG_SCI
	DebugCom("Beta'=E(0) or E(1) (copied)\t", ucSendPtr, sLen, idx, sDHidx);
	#endif

//	mSendMtx->lock();
//	mSendQueue->push(ucSendPtr);
//	mSendMtx->unlock();
//	mSendCV->notify_all();			// Communication thread가 아니라 PPkNN thread가 notify되는 것은 아닌지?

	try {
		mCSocket->send(ucSendPtr, sLen);
	}
	catch ( SocketException& e ) {
		std::cout << "Exception: " << e.description() << std::endl;
	}

	#ifdef _DEBUG_Assert
	// checking the allocated size  of GMP
	assert(	 pV.m->_mp_alloc >= GMP_N_SIZE);
	assert(   pT.m->_mp_alloc == 1);
	assert(	 cV.c->_mp_alloc == 2*GMP_N_SIZE);
	assert(cB.c->_mp_alloc >= 1);
	#endif

	memset(ucRecvPtr, 0, HED_SIZE+2*ENC_SIZE);
	ucRecvPtr[1] = 0xff;

	return 0;
}

//bool PaillierCrypto::SCF(unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, th_t* tSend)
bool PaillierCrypto::SCF(unsigned short idx, unsigned char* ucRecvPtr)
{
	paillier_plaintext_t  pU, pV;
	paillier_ciphertext_t cV, cU;

	#ifdef _DEBUG_INIT_1
	mpz_inits(pU.m, pV.m, cV.c, cU.c, NULL);
	#else
	mpz_init2(pU.m, 2*GMP_N_SIZE+1);
	mpz_init2(pV.m, 1);
	mpz_init2(cV.c, 3*GMP_N_SIZE);
	mpz_init2(cU.c, 2*GMP_N_SIZE);
	#endif

	unsigned char bV[ENC_SIZE] = {0, };
	unsigned char ucSendPtr[HED_SIZE+ENC_SIZE] = {0, };
	short sLen, sDHidx;

	// U'
    sDHidx = Byte2Short(ucRecvPtr);
	sLen = Byte2Short(ucRecvPtr+HED_LEN);
	#ifdef _DEBUG_SCF
    DebugCom("U' (Hex)\t\t\t\t", ucRecvPtr, sLen+HED_SIZE, idx, sDHidx);
	#endif

	#ifdef _DEBUG_Assert
    assert(sLen == ENC_SIZE);
	#endif

	paillier_ciphertext_from_bytes(&cU, ucRecvPtr+HED_SIZE, ENC_SIZE);
	#ifdef _DEBUG_SCF
	DebugDec("U (Copied)\t\t\t", &cU, idx, sDHidx);
	#endif

	// u = D(U)
	paillier_dec(&pU, mPubKey, mPrvKey, &cU);
	#ifdef _DEBUG_SCF
	DebugOut("Decrypted u = D(U)\t\t", pU.m, idx, sDHidx);
	#endif

	// (u==0) V=E(1), (u!=0) V=E(0)
	if (mpz_cmp_ui(pU.m, 0) == 0)
		mpz_set_ui(pV.m, 1);
	else
		mpz_set_ui(pV.m, 0);

	paillier_enc(&cV, mPubKey, &pV, paillier_get_rand_devurandom);
	#ifdef _DEBUG_SCF
	//DebugOut("(u==0) V=E(1), (u!=0) V=E(0)", cV.c, idx, sDHidx);
	DebugDec("(u==0) V=E(1), (u!=0) V=E(0)\t", &cV, idx, sDHidx);
	#endif

	// send V'
	paillier_ciphertext_to_bytes(bV, ENC_SIZE, &cV);
	#ifdef _DEBUG_SCF
	DebugCom("V' (Hex)\t\t\t", bV, ENC_SIZE, idx, sDHidx);
	#endif

    sLen = ENC_SIZE;
	SetSendMsg(ucSendPtr, ucRecvPtr, bV, sLen);
    sLen += HED_SIZE;
	#ifdef _DEBUG_SCF
	DebugCom("h' = E(h) (copied)\t\t", ucSendPtr, sLen, idx, sDHidx);
	#endif

//	mSendMtx->lock();
//	mSendQueue->push(ucSendPtr);
//	mSendMtx->unlock();
//	mSendCV->notify_all();			// Communication thread가 아니라 PPkNN thread가 notify되는 것은 아닌지?

	try {
		mCSocket->send(ucSendPtr, sLen);
	}
	catch ( SocketException& e ) {
		std::cout << "Exception: " << e.description() << std::endl;
	}

	#ifdef _DEBUG_Assert
	// checking the allocated size  of GMP
	assert(pU.m->_mp_alloc <= 2*GMP_N_SIZE+1);
	assert(pV.m->_mp_alloc == 1);
	assert(cV.c->_mp_alloc <= 3*GMP_N_SIZE);
	assert(cU.c->_mp_alloc == 2*GMP_N_SIZE);
	#endif

	memset(ucRecvPtr, 0, HED_SIZE+2*ENC_SIZE);
	ucRecvPtr[1] = 0xff;

	return true;
}

//void PaillierCrypto::TerminatePgm(unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, th_t* tSend)
void PaillierCrypto::TerminatePgm(unsigned short idx, unsigned char* ucRecvPtr)
{
	short sLen, sDHidx;

	sDHidx = Byte2Short(ucRecvPtr);
	sLen = Byte2Short(ucRecvPtr+HED_LEN);
	#ifdef _DEBUG_TERMINATE_PGM
    DebugCom("Terminate Program (received)\t", ucRecvPtr, sLen+HED_SIZE, idx, sDHidx);
	#endif

	#ifdef _DEBUG_Assert
	assert(sLen == 3);
	#endif

	delete[] ucRecvPtr;

	return;
}

inline void PaillierCrypto::SetSendMsg(unsigned char* ucSendPtr, const unsigned char* ucRecvPtr, unsigned char* Data, const unsigned short Len)
{
    //memset(ucSendPtr, 0, HED_SIZE+ENC_SIZE);
    memcpy(ucSendPtr, ucRecvPtr, HED_LEN);
	ucSendPtr[3] = (unsigned char)(Len & 0x000000ff);
	ucSendPtr[4] = (unsigned char)((Len & 0x0000ff00) >> 8);
    memcpy(ucSendPtr+HED_SIZE, Data, Len);
	//delete[] Data;

	return;
}

inline void PaillierCrypto::SetSendMsg(unsigned char* ucSendPtr, const unsigned char* ucRecvPtr, unsigned char bData)
{
    //memset(ucSendPtr, 0, HED_SIZE+ENC_SIZE);
    memcpy(ucSendPtr, ucRecvPtr, HED_LEN);
    ucSendPtr[HED_LEN]  = 1;
    ucSendPtr[HED_SIZE] = bData;

	return;
}

inline void PaillierCrypto::DebugOut(const mpz_t pData)
{
	gmp_printf("3-*DD* %ZX\n", pData);
	return;
}

inline void PaillierCrypto::DebugOut(const char* pMsg, const mpz_t pData)
{
	gmp_printf("2-[CSP] %s : %ZX\n", pMsg, pData);
	return;
}

inline void PaillierCrypto::DebugOut(const char* pMsg, const mpz_t pData, const short idx, const short DHidx)
{
	gmp_printf("[%03d-CSP-%03d] %s : %ZX\n", idx, DHidx, pMsg, pData);
	return;
}

inline void PaillierCrypto::DebugOut(const char* pMsg, const unsigned char* pData)
{
	printf("1-[CSP] %s : %s \n", pMsg, pData);
	return;
}

inline void PaillierCrypto::DebugOut(const char* pMsg, const unsigned char* pData, const short idx, const short DHidx)
{
	printf("[%03d-CSP-%03d] %s : %s\n", idx, DHidx, pMsg, pData);
	return;
}

inline void PaillierCrypto::DebugOut(const char* pMsg, short pData, const short idx, const short DHidx)
{
	printf("[%03d-CSP-%03d] %s : %d\n", idx, DHidx, pMsg, pData);
	return;
}

inline void PaillierCrypto::DebugDec(paillier_ciphertext_t* cTxt)
{
	paillier_plaintext_t m;
	#ifdef _DEBUG_INIT_1
	mpz_init(m.m);
	#else
	mpz_init2(m.m, GMP_N_SIZE+1);
	#endif
	paillier_dec(&m, mPubKey, mPrvKey, cTxt);
	gmp_printf("5-*DH* %ZX\n", &m);

	#ifdef _DEBUG_Assert
	assert(m.m->_mp_alloc ==   GMP_N_SIZE+1);
	assert(0);
	#endif

    return;
}

inline void PaillierCrypto::DebugDec(const char* pMsg, paillier_ciphertext_t* cTxt)
{
	paillier_plaintext_t m;
	#ifdef _DEBUG_INIT_1
	mpz_init(m.m);
	#else
	mpz_init2(m.m, GMP_N_SIZE+1);
	#endif
	paillier_dec(&m, mPubKey, mPrvKey, cTxt);
	gmp_printf("[CSP] %s : %ZX\n", pMsg, &m);

	#ifdef _DEBUG_Assert
	assert(m.m->_mp_alloc ==   GMP_N_SIZE+1);
	assert(0);
	#endif

    return;
}

inline void PaillierCrypto::DebugDec(const char* pMsg, paillier_ciphertext_t* cTxt, const short idx, const short DHidx)
{
	paillier_plaintext_t m;
	#ifdef _DEBUG_INIT_1
	mpz_init(m.m);
	#else
	mpz_init2(m.m, 2*GMP_N_SIZE+1);
	#endif
	paillier_dec(&m, mPubKey, mPrvKey, cTxt);
	gmp_printf("[%03d-CSP-%03d] %s : %ZX\n", idx, DHidx, pMsg, &m);

	#ifdef _DEBUG_Assert
	assert(m.m->_mp_alloc <= 2*GMP_N_SIZE+1);
	#endif

    return;
}

inline void PaillierCrypto::DebugCom(const char* pMsg, const unsigned char *data, int len)
{
	constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
							   '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	char s[len*2+1]={0,};
	for (int i = 0; i < len; ++i) {
		s[2*i]	 = hexmap[(data[i] & 0xF0) >> 4];
		s[2*i+1] = hexmap[data[i] & 0x0F];
	}
	printf("[CSP] %s : %s\n", pMsg, s);

	return;
}

inline void PaillierCrypto::DebugCom(const char* pMsg, unsigned char *data, int len, const short idx, const short DHidx)
{
	constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
							   '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	char s[len*2+1]={0,};
	for (int i = 0; i < len; ++i) {
		s[2*i]	 = hexmap[(data[i] & 0xF0) >> 4];
		s[2*i+1] = hexmap[data[i] & 0x0F];
	}
	printf("[%03d-CSP-%03d] %s : %s\n", idx, DHidx, pMsg, s);

	return;
}

void PaillierCrypto::DebugComMain(const char* pMsg, unsigned char *data, int len, const short idx, const short DHidx)
{
	constexpr char hexmap[] = {'0', '1', '2', '3', '4', '5', '6', '7',
							   '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
	char s[len*2+1]={0,};
	for (int i = 0; i < len; ++i) {
		s[2*i]	 = hexmap[(data[i] & 0xF0) >> 4];
		s[2*i+1] = hexmap[data[i] & 0x0F];
	}
	printf("[%03d-CSP-%03d] %s : %s\n", idx, DHidx, pMsg, s);

	return;
}

//inline void PaillierCrypto::Short2Byte(unsigned char* Ret, unsigned short In)
//{
//	Ret[1] = (unsigned char)((In & 0x0000ff00) >> 8);
//	Ret[0] = (unsigned char)(In & 0x000000ff);
//	return;
//}

inline unsigned short PaillierCrypto::Byte2Short(unsigned char* In)
{
	return (In[1]<<8) + In[0];
}

inline void PaillierCrypto::paillier_ciphertext_from_bytes(paillier_ciphertext_t* ct, void* c, int len )
{
	mpz_import(ct->c, len, 1, 1, 0, 0, c);
	return;
}

inline void PaillierCrypto::paillier_ciphertext_to_bytes(unsigned char* buf, int len, paillier_ciphertext_t* ct )
{
	int cur_len;
	cur_len = mpz_sizeinbase(ct->c, 2);
	cur_len = PAILLIER_BITS_TO_BYTES(cur_len);
	mpz_export(buf + (len - cur_len), 0, 1, 1, 0, 0, ct->c);
	return;
}

//int PaillierCrypto::Sender(th_t* tSend)
//{
//	unsigned char* ucSendPtr;
//	short sIdx, sLen, sKillCnt=0;
//	std::unique_lock<std::mutex> ulSend(tSend->m, std::defer_lock);
//
//	while (1) {
//		ulSend.lock();
//		tSend->cv.wait(ulSend, [&] {return !tSend->q.empty();});
//
//		ucSendPtr = tSend->q.front();
//		tSend->q.pop();
//		ulSend.unlock();
//
//		if (*(ucSendPtr+2) == COM_TERM) {
//			assert(*(ucSendPtr+HED_SIZE) == 0xff);
//			sKillCnt++;
//			if (sKillCnt < NUM_PPkNN_THREAD) {
//				DebugOut("Kill Message Count\t\t", sKillCnt, 999, sIdx);
//				delete[] ucSendPtr;
//				continue;
//			}
//			else {		// sKillCnt >= NUM_PPkNN_THREAD
//				sIdx = Byte2Short(ucSendPtr);
//				sLen = Byte2Short(ucSendPtr+HED_LEN)+HED_SIZE;
//
//				#ifdef _DEBUG_Communication
//				DebugCom("(Sender Thread) SendBuf (Hex)\t", ucSendPtr, sLen, 999, sIdx);
//				#endif
//
//				try {
//					mCSocket->send(ucSendPtr, sLen);
//				}
//				catch ( SocketException& e ) {
//					std::cout << "Exception: " << e.description() << std::endl;
//				}
//
//				delete[] ucSendPtr;
//				return 0;
//			}
//		}
//
//		sIdx = Byte2Short(ucSendPtr);
//		sLen = Byte2Short(ucSendPtr+HED_LEN)+HED_SIZE;
//
////		// temp
////		if (sIdx>100) {
////			DebugCom("(Sender Thread) Error Msg (Hex)\t", ucSendPtr, HED_SIZE+2*ENC_SIZE, 999, sIdx);
////			assert(0);
////		}
//
//		#ifdef _DEBUG_Communication
//		DebugCom("(Sender Thread) SendBuf (Hex)\t", ucSendPtr, sLen, 999, sIdx);
//		#endif
//
//		//?? exception 출력, connection reset by peer (errno=104) 처리
//		try {
//			mCSocket->send(ucSendPtr, sLen);
//		}
//		catch ( SocketException& e ) {
//			std::cout << "Exception: " << e.description() << std::endl;
//		}
//	}
//}

int PaillierCrypto::Receiver(th_t* tRecv)
{
	unsigned char* ucRecvBuf[NUM_PPkNN_THREAD];
	short sIdx, sLen, sbx=0;
	int iReceivedLen;

	for (int i=0 ; i<NUM_PPkNN_THREAD ; i++) {
		ucRecvBuf[i] = new unsigned char[HED_SIZE+2*ENC_SIZE];
		memset(ucRecvBuf[i], 0, HED_SIZE+2*ENC_SIZE);
		ucRecvBuf[i][1] = 0xff;
	}

	while (1) {
		while (ucRecvBuf[sbx][1]!=0xff) {
			sbx++;
			if (sbx>=NUM_PPkNN_THREAD)
				sbx=0;
		}
		iReceivedLen=0;

		//?? exception 출력, connection reset by peer (errno=104) 처리
		try {
			iReceivedLen = mCSocket->recv(ucRecvBuf[sbx], HED_SIZE);
			sLen = Byte2Short(ucRecvBuf[sbx]+HED_LEN);
			while (iReceivedLen != HED_SIZE+sLen)
				iReceivedLen += mCSocket->recv(ucRecvBuf[sbx]+iReceivedLen, HED_SIZE+sLen-iReceivedLen);
	    }
		catch ( SocketException& e ) {
			std::cout << "Exception: " << e.description() << std::endl;
		}

		sIdx = Byte2Short(ucRecvBuf[sbx]);

		#ifdef _DEBUG_Communication
	    DebugCom("(Receiver Thread) RecvBuf (Hex)\t", ucRecvBuf[sbx], HED_SIZE+sLen, 999, sIdx);
		#endif

		if (*(ucRecvBuf[sbx]+2) == COM_TERM) {
			assert(*(ucRecvBuf[sbx]+HED_SIZE) == 0xff);
			unsigned char ucKillMsg[HED_SIZE+3] = {0, };
			memcpy(ucKillMsg, ucRecvBuf[sbx], HED_LEN);
			ucKillMsg[HED_LEN] = 3;
			ucKillMsg[HED_SIZE+0] = (unsigned char) (MOD_SIZE & 0x000000ff);
			ucKillMsg[HED_SIZE+1] = (unsigned char)((MOD_SIZE & 0x0000ff00) >> 8);
			ucKillMsg[HED_SIZE+2] = NUM_PPkNN_THREAD;
			try {
				mCSocket->send(ucKillMsg, sizeof(ucKillMsg));
			}
			catch ( SocketException& e ) {
				std::cout << "Exception: " << e.description() << std::endl;
			}

			for (int i=0 ; i<NUM_PPkNN_THREAD ; i++) {
				memcpy(ucRecvBuf[i], ucKillMsg, HED_SIZE+1);
				tRecv->m.lock();
				tRecv->q.push(ucRecvBuf[i]);
				tRecv->cv.notify_one();
				tRecv->m.unlock();
			}

			return 0;
		}

		tRecv->m.lock();
		tRecv->q.push(ucRecvBuf[sbx]);
		tRecv->cv.notify_one();
		tRecv->m.unlock();
	}

	return 0;
}




//int PaillierCrypto::Comparison(unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, cmp_t* tCmp, th_t* tSend)
int PaillierCrypto::Comparison1(unsigned short idx, unsigned char* ucRecvPtr)
{
	paillier_plaintext_t  pV;
	paillier_ciphertext_t cV;

	#ifdef _DEBUG_INIT_1
	mpz_inits(pV.m, cV.c, NULL);
	#else
	mpz_init2(pV.m, 1);
	mpz_init2(cV.c, 2*GMP_N_SIZE);
	#endif

	unsigned char ucSendPtr[HED_SIZE+1] = {0, };				//?? HED_SIZE+1만큼 전송할때 문제가 되지 않는지?
	int iRes;
	char bBeta;
	short sLen, sDHidx;

    sDHidx = Byte2Short(ucRecvPtr);
	sLen = Byte2Short(ucRecvPtr+HED_LEN);
	#ifdef _DEBUG_Comparison
	DebugCom("V' (Hex)\t\t\t\t", ucRecvPtr, sLen+HED_SIZE, idx, sDHidx);
	#endif

	#ifdef _DEBUG_Assert
	assert(sLen == ENC_SIZE);
	#endif

	// V' = E(r*(Cnt-k))
	paillier_ciphertext_from_bytes(&cV, ucRecvPtr+HED_SIZE, ENC_SIZE);
	#ifdef _DEBUG_Comparison
	DebugOut("V (Copied)\t\t\t", cV.c, idx, sDHidx);
	#endif

	// y = D(Y) = r*(Cnt-k) or = r*(k-Cnt)
	paillier_dec(&pV, mPubKey, mPrvKey, &cV);
	#ifdef _DEBUG_Comparison
    DebugOut("Decrypted V = r(Cnt-k)\t\t", pV.m, idx, sDHidx);
	#endif

    // send gamma (result)
    iRes = mpz_cmp_ui(pV.m, 0);
    if (iRes==0)  	{ bBeta = 0; }		// Success
    else	    	{ bBeta = 1; }		// Fail

	SetSendMsg(ucSendPtr, ucRecvPtr, bBeta);
    sLen = HED_SIZE+1;
	#ifdef _DEBUG_Comparison
	DebugCom("Beta (copied)\t\t\t", ucSendPtr, sLen, idx, sDHidx);
	#endif

//	mSendMtx->lock();
//	mSendQueue->push(ucSendPtr);
//	mSendMtx->unlock();
//	mSendCV->notify_all();			// Communication thread가 아니라 PPkNN thread가 notify되는 것은 아닌지?

	try {
		mCSocket->send(ucSendPtr, sLen);
	}
	catch ( SocketException& e ) {
		std::cout << "Exception: " << e.description() << std::endl;
	}

	#ifdef _DEBUG_Assert
	// checking the allocated size  of GMP
	assert(   pV.m->_mp_alloc >=   GMP_N_SIZE);
	assert(	  cV.c->_mp_alloc == 2*GMP_N_SIZE);
	#endif

	memset(ucRecvPtr, 0, HED_SIZE+2*ENC_SIZE);
	ucRecvPtr[1] = 0xff;

	return iRes;
}

//int PaillierCrypto::Comparison(unsigned short idx, unsigned char* ucRecvPtr, unsigned char* ucSendPtr, cmp_t* tCmp, th_t* tSend)
int PaillierCrypto::Comparison2(unsigned short idx, unsigned char* ucRecvPtr)
{
	paillier_plaintext_t  pUj, pT;
	paillier_ciphertext_t cUj, cBeta;

	#ifdef _DEBUG_INIT_1
	mpz_inits(pUj.m, pT.m, cUj.c, cBeta.c, cBeta.c, NULL);
	#else
	mpz_init2(pUj.m, 2*GMP_N_SIZE+1);
	mpz_init2(pT.m, 1);
	mpz_init2(cUj.c, 2*GMP_N_SIZE);
	mpz_init2(cBeta.c, 2*GMP_N_SIZE);
	#endif

	unsigned char bBeta[ENC_SIZE] = {0, };
	unsigned char ucSendPtr[HED_SIZE+ENC_SIZE] = {0, };				//?? HED_SIZE+1만큼 전송할때 문제가 되지 않는지?
	int iRes, iZero, iOne, iTmp;
	short sLen, sDHidx;

    sDHidx = Byte2Short(ucRecvPtr);
	sLen = Byte2Short(ucRecvPtr+HED_LEN);
	#ifdef _DEBUG_Comparison
	DebugCom("Uj' (Hex)\t\t\t\t", ucRecvPtr, sLen+HED_SIZE, idx, sDHidx);
	#endif

	#ifdef _DEBUG_Assert
	assert(sLen == ENC_SIZE);
	#endif

	// U_j'
	paillier_ciphertext_from_bytes(&cUj, ucRecvPtr+HED_SIZE, ENC_SIZE);
	#ifdef _DEBUG_Comparison
	DebugOut("Encrypted Uj (Copied)\t\t", cUj.c, idx, sDHidx);
	#endif

	// U_j = D(U_j')
	paillier_dec(&pUj, mPubKey, mPrvKey, &cUj);
	#ifdef _DEBUG_Comparison
    DebugOut("Decrypted Uj\t\t\t", pUj.m, idx, sDHidx);
	#endif

    // compare with 0, (N-1)/2, N
    iZero = mpz_cmp_d(pUj.m, 0);
    iOne  = mpz_cmp_d(pUj.m, 1);

    // send gamma (result)
    if ((iZero==0)||(iOne==0)) {
    	if (iZero==0)	iTmp=0;
    	else			iTmp=1;

    	mpz_set_ui(pT.m, iTmp);
    	paillier_enc(&cBeta, mPubKey, &pT, paillier_get_rand_devurandom);
    	iRes = 0;
		#ifdef _DEBUG_Comparison
		DebugDec("Beta'=E(0) or E(1)\t\t", &cBeta, idx, sDHidx);
		#endif

	    paillier_ciphertext_to_bytes(bBeta, ENC_SIZE, &cBeta);
		#ifdef _DEBUG_Comparison
		DebugCom("Beta'=E(0) or E(1) (Hex)\t\t", bBeta, ENC_SIZE, idx, sDHidx);
		#endif

	    sLen = ENC_SIZE;
		SetSendMsg(ucSendPtr, ucRecvPtr, bBeta, sLen);
	    sLen += HED_SIZE;
		#ifdef _DEBUG_Comparison
		DebugCom("Beta'=E(0) or E(1) (copied)\t", ucSendPtr, sLen, idx, sDHidx);
		#endif
    }
    else {
    	iRes = 1;

		SetSendMsg(ucSendPtr, ucRecvPtr, (unsigned char)iRes);
	    sLen = HED_SIZE+1;
		#ifdef _DEBUG_Comparison
		DebugCom("(continue message)\t\t", ucSendPtr, sLen, idx, sDHidx);
		#endif
    }

//	mSendMtx->lock();
//	mSendQueue->push(ucSendPtr);
//	mSendMtx->unlock();
//	mSendCV->notify_all();			// Communication thread가 아니라 PPkNN thread가 notify되는 것은 아닌지?

	try {
		mCSocket->send(ucSendPtr, sLen);
	}
	catch ( SocketException& e ) {
		std::cout << "Exception: " << e.description() << std::endl;
	}

	#ifdef _DEBUG_Assert
	// checking the allocated size  of GMP
	assert(	 pUj.m->_mp_alloc >= GMP_N_SIZE);
	assert(   pT.m->_mp_alloc == 1);
	assert(	 cUj.c->_mp_alloc == 2*GMP_N_SIZE);
	assert(cBeta.c->_mp_alloc >= 1);
	#endif

	memset(ucRecvPtr, 0, HED_SIZE+2*ENC_SIZE);
	ucRecvPtr[1] = 0xff;

	return iRes;
}
