//============================================================================
// Name        : PPkNNDH.cpp
// Author      : PJS
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================


#include <iostream>
#include "PaillierCrypto.h"
#include <time.h>
#include <vector>
#include <thread>
#include <chrono>	// temp

using namespace std;

void Initialization(in_t* tIn, out_t* tOut, skle_1_t* tSkle1);
void PrintResult(double* ResTime, short sTrd);

//void PPkNNTrd(PaillierCrypto *oCrypto, sync_t* tSync, out_t *tOut, in_t *tIn, unsigned short idx, thp_t* tRecv, th_t* tSend)
void PPkNNTrd(unsigned short idx, in_t *tIn, out_t *tOut, skle_1_t* tSkle1, PaillierCrypto *oCrypto, sync_t* tSync, thp_t* tRecv)
{
	//unsigned char* ucSendBuf = new unsigned char[HED_SIZE+2*ENC_SIZE];
	unique_lock<mutex> ulSync(tSync->m, defer_lock);
	pre_t tPre;
	skle_e_t tSklee;
	unsigned int *pSyncCnt2, *pSyncCnt1;
//	int iSrt, iEnd;
	bool bFirst = true;

	#ifdef _DEBUG_THREAD
	printf("<<<  %03d - th Thread start  >>>\n", idx);
	#endif

	oCrypto->PreComputation(&tPre, &tSklee, tOut, tIn, idx);


	// ************************   Squared Distance   ************************ //

	#ifdef _DEBUG_MAIN_1
	ulSync.lock();
    (tSync->c1)++;
	#ifdef _DEBUG_THREAD
	printf("(Count: %02d) <<<  %03d - th Thread : continuing  >>>\n", tSync->c1, idx);
	#endif
    if (tSync->c1 < THREAD1_NUM) {
    	tSync->cv.wait(ulSync, [&] {return tSync->c1>=THREAD1_NUM;});
    }
    else {
    	printf("\n************   Squared Distance   ************\n\n");
		tSync->cv.notify_all();		tSync->c2=0;
		tOut->start = time(NULL);						// compute time
    }
	ulSync.unlock();
	#endif

	// compute Squared Distance
	//oCrypto->SquaredDist(tOut, tIn, &tPre, idx, tRecv, tSend, ucSendBuf);
	oCrypto->SquaredDist(tOut, tIn, &tPre, idx, tRecv);

	// print the result of Squared Distance for debugging
	#ifdef _DEBUG_MAIN_1
	ulSync.lock();
    (tSync->c2)++;
    if (tSync->c2 < THREAD1_NUM) {
    	tSync->cv.wait(ulSync, [&] {return tSync->c2>=THREAD1_NUM;});
    }
    else {
    	tOut->end = time(NULL);		tOut->dTime[0] = (double) (tOut->end-tOut->start);
    	printf("[DH-%03d] Time : %f (seconds) \n", idx, tOut->dTime[0]);

		oCrypto->DebugOutMain("N\t\t\t", oCrypto->GetPubKey()->n, idx);
		for (int i=0 ; i<DATA_NUM ; i++) {
			printf("%02d - ", i);
			oCrypto->DebugDecMain("s'_i (plaintext)\t", &(tOut->cDist[i]), idx);
		}
		tSync->cv.notify_all();		tSync->c1=0;
    }
	ulSync.unlock();
	#endif


	// ************************   Secure Bit-Decomposition   ************************ //

	#ifdef _DEBUG_MAIN_1
	ulSync.lock();
	(tSync->c1)++;
	#ifdef _DEBUG_THREAD
	printf("(Count: %02d) <<<  %03d - th Thread : continuing  >>>\n", tSync->c1, idx);
	#endif
	if (tSync->c1 < THREAD1_NUM) {
		tSync->cv.wait(ulSync, [&] {return tSync->c1>=THREAD1_NUM;});
	}
	else {
		printf("\n************   Secure Bit-Decomposition   ************\n\n");
		tSync->cv.notify_all();		tSync->c2=0;
		tOut->start = time(NULL);
	}
	ulSync.unlock();
	#endif

	// compute Secure Bit-Decomposition
	//oCrypto->SecBitDecomp(tOut, &tSkle, &tPre, bFirst, idx, tRecv, tSend, ucSendBuf);
	oCrypto->SecBitDecomp(tOut, &tSklee, tSkle1, &tPre, bFirst, idx, tRecv);

	// print the result of Squared Distance for debugging
	#ifdef _DEBUG_MAIN_1
	ulSync.lock();
	(tSync->c2)++;
	if (tSync->c2 < THREAD1_NUM) {
		tSync->cv.wait(ulSync, [&] {return tSync->c2>=THREAD1_NUM;});
	}
	else {
		tOut->end = time(NULL);		tOut->dTime[1] = (double) (tOut->end-tOut->start);
		printf("[DH-%03d] Time : %f (seconds) \n", idx, tOut->dTime[1]);

		for (int i=0 ; i<DATA_NUM ; i++) {
			printf("%02d - ", i);
			oCrypto->DebugDecMain("bit decomposed s'_i (plaintext) ", &(tOut->cDist[i]), idx);

		    for (int j=DATA_SQUARE_LENGTH-1 ; j>=0 ; j--) {
				oCrypto->DebugDecBitMain(&(tOut->cDisB[i][j]));
				if (j%8==0)		printf("\t");
				if (j%64==0)	printf("\n");
			}
		}
		tSync->cv.notify_all();		tSync->c1=0;
	}
	ulSync.unlock();
	#endif


	// **********************************   SkLE_s    ********************************** //

	#ifdef _DEBUG_MAIN_1
	ulSync.lock();
	(tSync->c1)++;
	#ifdef _DEBUG_THREAD
	printf("(Count: %02d) <<<  %03d - th Thread : continuing  >>>\n", tSync->c1, idx);
	#endif
	if (tSync->c1 < THREAD1_NUM) {
		tSync->cv.wait(ulSync, [&] {return tSync->c1>=THREAD1_NUM;});
	}
	else {
		printf("\n************   SkLE_s   ************\n\n");
		tSync->cv.notify_all();		tSync->c2=0;
		tOut->start = time(NULL);
	}
	ulSync.unlock();
	#endif

	///////////////////////// SkLE_s start /////////////////////////

	oCrypto->SkLE_s_Init(tOut, &tSklee, &tPre, bFirst, idx);

	for (int j=DATA_SQUARE_LENGTH-1 ; j>=0 ; j--) {			// j = l-1 ~ 0

		///////////////////////// Step 1 /////////////////////////

		oCrypto->SkLE_s_1(tOut, &tSklee, &tPre, j, bFirst, idx, tRecv);

		///////////////////////// Step 2,3,4 /////////////////////////

		ulSync.lock();
		#if (DATA_SQUARE_LENGTH-1) % 2 == 0
		if (j%2 == 0) 		{	pSyncCnt2 = &(tSync->c2);	pSyncCnt1 = &(tSync->c1);	}
		else 					{	pSyncCnt2 = &(tSync->c1);	pSyncCnt1 = &(tSync->c2);	}
		#else
		if (j%2 == 0) 		{	pSyncCnt2 = &(tSync->c1);	pSyncCnt1 = &(tSync->c2);	}
		else 					{	pSyncCnt2 = &(tSync->c2);	pSyncCnt1 = &(tSync->c1);	}
		#endif

		(*pSyncCnt2)++;
		if (*pSyncCnt2 < THREAD1_NUM) {
			tSync->cv.wait(ulSync, [&] {return *pSyncCnt2>=THREAD1_NUM;});
		}
		else {
			oCrypto->SkLE_s_234(tOut, &tSklee, tSkle1, &tPre, j, bFirst, idx, tRecv);
			tSync->cv.notify_all();		*pSyncCnt1=0;
		}
		ulSync.unlock();

		///////////////////////// Step 4 /////////////////////////

		oCrypto->SkLE_s_4(tOut, &tSklee, tSkle1, j, bFirst, idx, tRecv);
	}

	// K[i] = K[i] * C[i] (i = 1~n)
	oCrypto->SkLE_s_5(tOut, &tSklee, bFirst, idx);

	// (tSync->c1), Top-k data를 찾은 경우, 2의 순서를 맞추기 위해서 한번더 수행함.
	if (DATA_SQUARE_LENGTH%2 != 0) {
		ulSync.lock();
		(tSync->c1)++;
		if (tSync->c1 < THREAD1_NUM) {
			tSync->cv.wait(ulSync, [&] {return tSync->c1>=THREAD1_NUM;});
		}
		else {
			tSync->cv.notify_all();		tSync->c2=0;
		}
		ulSync.unlock();
	}


//	// 결과 복사
//	iSrt = tOut->iRan[idx];
//	iEnd = tOut->iRan[idx+1];
//	if (tOut->iCmp == 1) {
//		for (int i=iSrt ; i<iEnd ; i++)
//			tOut->cK[i] = tSkle.cTRes[i-iSrt];
//	}
//	else if (tOut->iCmp == 2) {
//		iNum = tOut->iRan[idx+1]-tOut->iRan[idx];		// iNum 재사용
//		iBit = tOut->iRan[idx];							// iBit 재사용
//		for (int i=0 ; i<iNum ; i++) {
//			paillier_mul(oCrypto->GetPubKey(), &(tOut->cK[iSrt+i]), &(tSkle.cIRes[i]), &(tSkle.cCan[i]));
//		}
//	}
//	else
//		assert(0);

	///////////////////////// SkLE_s code end /////////////////////////

	// print the result of SkLE_s
	#ifdef _DEBUG_MAIN_1
	ulSync.lock();
    (tSync->c2)++;
    if (tSync->c2 < THREAD1_NUM) {
    	tSync->cv.wait(ulSync, [&] {return tSync->c2>=THREAD1_NUM;});
    }
    else {
    	tOut->end = time(NULL);		tOut->dTime[2] = (double) (tOut->end-tOut->start);		// compute time
    	printf("[DH-%03d] Time : %f (seconds) \n", idx, tOut->dTime[2]);

//    	printf("[DH-%03d] Found bit : %d \n", idx, tSkle.iFoundBit[0]);
    	for (int i=0 ; i<DATA_NUM ; i++) {
    		printf("%02d - ", i);
    		oCrypto->DebugDecMain("K[i] (plaintext) ", &(tOut->cK[i]), idx);
    	}
		tSync->cv.notify_all();		tSync->c1=0;
    }
	ulSync.unlock();
	#endif


	// ************************   Class Frequency of Top-k Data (SCF)   ************************ //

	#ifdef _DEBUG_MAIN_1
	ulSync.lock();
	(tSync->c1)++;
	#ifdef _DEBUG_THREAD
	printf("(Count: %02d) <<<  %03d - th Thread : continuing  >>>\n", tSync->c1, idx);
	#endif
	if (tSync->c1 < THREAD1_NUM) {
		tSync->cv.wait(ulSync, [&] {return tSync->c1>=THREAD1_NUM;});
	}
	else {
		printf("\n************   Class Frequency of Top-k Data (SCF)   ************\n\n");
		tSync->cv.notify_all();		tSync->c2=0;
		tOut->start = time(NULL);						// compute time
	}
	ulSync.unlock();
	#endif

	// compute Class Frequency of Top-k Data (SCF)
	//oCrypto->SCF(tOut, tIn, &tPre, idx, tRecv, tSend, ucSendBuf);
	oCrypto->SCF(tOut, tIn, &tPre, idx, tRecv);

	// print the result of SCF for debugging
	#ifdef _DEBUG_MAIN_1
	ulSync.lock();
    (tSync->c2)++;
    if (tSync->c2 < THREAD1_NUM) {
    	tSync->cv.wait(ulSync, [&] {return tSync->c2>=THREAD1_NUM;});
    }
    else {
    	// every thread의 결과 합치기
		for (int i=0 ; i<CLASS_SIZE ; i++) {
			mpz_set_ui(tOut->cFreq[i].c, 1);		// cFreq[i]=0
			for (int j=0 ; j<THREAD1_NUM ; j++)
				paillier_mul(oCrypto->GetPubKey(), &(tOut->cFreq[i]), &(tOut->cFreq[i]), &(tOut->cTFre[j][i]));
		}

		tOut->end = time(NULL);		tOut->dTime[3] = (double) (tOut->end-tOut->start);
		printf("[DH-%03d] Time : %f (seconds) \n", idx, tOut->dTime[3]);

		// print the result of SCF
		for (int i=0 ; i<CLASS_SIZE ; i++) {
			printf("%02d - ", i);
			oCrypto->DebugDecMain("Class Frequency of Top-k Data_i (plaintext)\t", &(tOut->cFreq[i]), idx);
		}
		tSync->cv.notify_all();		tSync->c1=0;
    }
	ulSync.unlock();
	#endif


	// ***   두번째 연산을 위한 thread 종료   *** //
	if (idx >= THREAD2_NUM) {
		printf("(Count: xx) <<<  %03d - th Thread END !!!  >>>\n", idx);
		return ;
	}
	bFirst = false;
	tSklee.bSkle = false;

	// ************************   Secure Bit-Decomposition for f'_j   ************************ //

	#ifdef _DEBUG_MAIN_1
	ulSync.lock();
	(tSync->c1)++;
	#ifdef _DEBUG_THREAD
	printf("(Count: %02d) <<<  %03d - th Thread : continuing  >>>\n", tSync->c1, idx);
	#endif
	if (tSync->c1 < THREAD2_NUM) {
		tSync->cv.wait(ulSync, [&] {return tSync->c1>=THREAD2_NUM;});
	}
	else {
		printf("\n************   Secure Bit-Decomposition (f'_j)   ************\n\n");
		tSync->cv.notify_all();		tSync->c2=0;
		tOut->start = time(NULL);						// compute time
	}
	ulSync.unlock();
	#endif

	// compute Secure Bit-Decomposition for f'_j
	//oCrypto->SecBitDecomp(tOut, &tSkle, &tPre, bFirst, idx, tRecv, tSend, ucSendBuf);
	oCrypto->SecBitDecomp(tOut, &tSklee, tSkle1, &tPre, bFirst, idx, tRecv);

	// print the result of Secure Bit-Decomposition of f'_j
	#ifdef _DEBUG_MAIN_1
	ulSync.lock();
	(tSync->c2)++;
	if (tSync->c2 < THREAD2_NUM) {
		tSync->cv.wait(ulSync, [&] {return tSync->c2>=THREAD2_NUM;});
	}
	else {
		tOut->end = time(NULL);		tOut->dTime[4] = (double) (tOut->end-tOut->start);		// compute time
		printf("[DH-%03d] Time : %f (seconds) \n", idx, tOut->dTime[4]);

		for (int i=0 ; i<CLASS_SIZE ; i++) {
			printf("%02d - ", i);
			oCrypto->DebugDecMain("bit decomposed f'_i (plaintext) ", &(tOut->cFreq[i]), idx);

		    for (int j=DATA_NUMBER_LENGTH-1 ; j>=0 ; j--) {
				oCrypto->DebugDecBitMain(&(tOut->cFreB[i][j]));
				if (j%8==0)		printf("\t");
				if (j%64==0)	printf("\n");
			}
		}
		tSync->cv.notify_all();		tSync->c1=0;
	}
	ulSync.unlock();
	#endif


	// **************************   SkLE_s (k=1, f'_j)    ************************** //

	#ifdef _DEBUG_MAIN_1
	ulSync.lock();
	(tSync->c1)++;
	#ifdef _DEBUG_THREAD
	printf("(Count: %02d) <<<  %03d - th Thread : continuing  >>>\n", tSync->c1, idx);
	#endif
	if (tSync->c1 < THREAD2_NUM) {
		tSync->cv.wait(ulSync, [&] {return tSync->c1>=THREAD2_NUM;});
	}
	else {
		printf("\n************   SkLE_s (k=1, f'_j)   ************\n\n");
		tSync->cv.notify_all();		tSync->c2=0;
		tOut->start = time(NULL);						// compute time
	}
	ulSync.unlock();
	#endif

	///////////////////////// SkLE_s (k=1, f'_j) code start /////////////////////////

	assert(tOut->iRan2[idx+1] - tOut->iRan2[idx] <= tOut->iRan[idx+1] - tOut->iRan[idx]);
	assert(THREAD2_NUM <= THREAD1_NUM);

	oCrypto->SkLE_s_Init(tOut, &tSklee, &tPre, bFirst, idx);

	for (int j=DATA_NUMBER_LENGTH-1 ; j>=0 ; j--) {			// j = l-1 ~ 0

		///////////////////////// Step 1 /////////////////////////

		oCrypto->SkLE_s_1(tOut, &tSklee, &tPre, j, bFirst, idx, tRecv);

		///////////////////////// Step 2,3,4 /////////////////////////

		ulSync.lock();
		#if (DATA_NUMBER_LENGTH-1) % 2 == 0
		if (j%2 == 0) 		{	pSyncCnt2 = &(tSync->c2);	pSyncCnt1 = &(tSync->c1);	}
		else 					{	pSyncCnt2 = &(tSync->c1);	pSyncCnt1 = &(tSync->c2);	}
		#else
		if (j%2 == 0) 		{	pSyncCnt2 = &(tSync->c1);	pSyncCnt1 = &(tSync->c2);	}
		else 					{	pSyncCnt2 = &(tSync->c2);	pSyncCnt1 = &(tSync->c1);	}
		#endif

		(*pSyncCnt2)++;
		if (*pSyncCnt2 < THREAD2_NUM) {
			tSync->cv.wait(ulSync, [&] {return *pSyncCnt2>=THREAD2_NUM;});
		}
		else {
			oCrypto->SkLE_s_234(tOut, &tSklee, tSkle1, &tPre, j, bFirst, idx, tRecv);
			tSync->cv.notify_all();		*pSyncCnt1=0;
		}
		ulSync.unlock();

		///////////////////////// Step 4 /////////////////////////

		oCrypto->SkLE_s_4(tOut, &tSklee, tSkle1, j, bFirst, idx, tRecv);
	}

	// K[i] = K[i] * C[i] (i = 1~n)
	oCrypto->SkLE_s_5(tOut, &tSklee, bFirst, idx);

	// (tSync->c1), Top-k data를 찾은 경우, 2의 순서를 맞추기 위해서 한번더 수행함.
	if (DATA_NUMBER_LENGTH%2 != 0) {
		ulSync.lock();
		(tSync->c1)++;
		if (tSync->c1 < THREAD2_NUM) {
			tSync->cv.wait(ulSync, [&] {return tSync->c1>=THREAD2_NUM;});
		}
		else {
			tSync->cv.notify_all();		tSync->c2=0;
		}
		ulSync.unlock();
	}

//	iNum=-1;
//	for (iBit=DATA_NUMBER_LENGTH ; iBit>=0 ; iBit--) {			// SkLE_s_Main을 위해서 마지막 한번더 실행 필요함.
//		iNum++;
//
//		#ifdef _DEBUG_THREAD
//		printf("\n<<<  %03d - th bit examination (IPE-FT1 for f'_j) >>>\n\n", iBit-1);
//		#endif
//
//		//oCrypto->SkLE_s_Main(tOut, &tSkle, &tPre, iBit-1, bFirst, idx, tRecv, tSend, ucSendBuf);
//		oCrypto->SkLE_s_Main(tOut, &tSkle, &tPre, iBit-1, bFirst, idx, tRecv);
//
//		ulSync.lock();
//		if (iNum%2 == 0) 	{	pSyncCnt2 = &(tSync->c2);	pSyncCnt1 = &(tSync->c1);	}
//		else 					{	pSyncCnt2 = &(tSync->c1);	pSyncCnt1 = &(tSync->c2);	}
//
//		(*pSyncCnt2)++;
//		if (*pSyncCnt2 < THREAD2_NUM) {
//			tSync->cv.wait(ulSync, [&] {return *pSyncCnt2>=THREAD2_NUM;});
//		}
//		else {
//			//oCrypto->SkLE_s_Cmp(tOut, &tSkle, &tPre, iBit-1, bFirst, idx, tRecv, tSend, ucSendBuf);
//			oCrypto->SkLE_s_Cmp(tOut, &tSkle, &tPre, iBit-1, bFirst, idx, tRecv);
//			tSync->cv.notify_all();		*pSyncCnt1=0;
//		}
//		ulSync.unlock();
//
//		// (tSync->c1), Top-k data를 찾은 경우, 2의 순서를 맞추기 위해서 한번더 수행함.
//		if (tOut->iCmp != 0) {
//			if (iNum%2 == 0) {
//				ulSync.lock();
//				(tSync->c1)++;
//				if (tSync->c1 < THREAD2_NUM)
//					tSync->cv.wait(ulSync, [&] {return tSync->c1>=THREAD2_NUM;});
//				else {
//					tSync->cv.notify_all();		tSync->c2=0;
//				}
//				ulSync.unlock();
//			}
//			tSkle.iFoundBit[1] = iBit;
//			break;
//		}
//	}	// (FOR-end) Finding Top-k data 종료
//
//	// 결과를 복사
//	iSrt = tOut->iRan2[idx];
//	iEnd = tOut->iRan2[idx+1];
//	if (tOut->iCmp == 1) {
//		for (int i=iSrt ; i<iEnd ; i++)
//			tOut->cFK[i] = tSkle.cTRes[i-iSrt];
//	}
//	else if (tOut->iCmp == 2) {
//		iNum = tOut->iRan2[idx+1]-tOut->iRan2[idx];		// iNum 재사용
//		iBit = tOut->iRan2[idx];							// iBit 재사용
//		for (int i=0 ; i<iNum ; i++)
//			paillier_mul(oCrypto->GetPubKey(), &(tOut->cFK[iSrt+i]), &(tSkle.cIRes[i]), &(tSkle.cCan[i]));
//	}
//	else
//		assert(0);



	///////////////////////// SkLE_s (k=1, f'_j) code end /////////////////////////

	// print the result of SkLE_s
	#ifdef _DEBUG_MAIN_1
	ulSync.lock();
    (tSync->c2)++;
    if (tSync->c2 < THREAD2_NUM) {
    	tSync->cv.wait(ulSync, [&] {return tSync->c2>=THREAD2_NUM;});
    }
    else {
    	tOut->end = time(NULL);		tOut->dTime[5] = (double) (tOut->end-tOut->start);		// compute time
    	printf("[DH-%03d] Time : %f (seconds) \n", idx, tOut->dTime[5]);

//    	printf("[DH-%03d] Found bit : %d \n", idx, tSkle.iFoundBit[1]);
    	for (int i=0 ; i<CLASS_SIZE ; i++) {
    		printf("%02d - ", i);
    		oCrypto->DebugDecMain("FK[i] (plaintext) ", &(tOut->cFK[i]), idx);
    	}
		tSync->cv.notify_all();		tSync->c1=0;
    }
	ulSync.unlock();
	#endif

	// checking the allocated size  of GMP
	#ifdef _DEBUG_Assert
	assert(tSkle.cTRes[0].c->_mp_alloc == 2*GMP_N_SIZE*2);
	assert(tSkle.cIRes[0].c->_mp_alloc == 2*GMP_N_SIZE*2);
	assert(tSkle. cCan[0].c->_mp_alloc == 2*GMP_N_SIZE*2);
//	assert(tSkle.	  cK.c->_mp_alloc == 2*GMP_N_SIZE);
	#endif

	// ************************   Computing mc'_j   ************************ //

	#ifdef _DEBUG_MAIN_1
	ulSync.lock();
    (tSync->c1)++;
	#ifdef _DEBUG_THREAD
	printf("(Count: %02d) <<<  %03d - th Thread : continuing  >>>\n", tSync->c1, idx);
	#endif
    if (tSync->c1 < THREAD2_NUM) {
    	tSync->cv.wait(ulSync, [&] {return tSync->c1>=THREAD2_NUM;});
    }
    else {
    	printf("\n************   Computing mc'_j   ************\n\n");
		tSync->cv.notify_all();		tSync->c2=0;
		tOut->start = time(NULL);						// compute time
    }
	ulSync.unlock();
	#endif

	// compute result class
	oCrypto->ComputeMc(tOut, tIn, idx);

	// print the result of result class for debugging
	#ifdef _DEBUG_MAIN_1
	ulSync.lock();
    (tSync->c2)++;
    if (tSync->c2 < THREAD2_NUM) {
    	tSync->cv.wait(ulSync, [&] {return tSync->c2>=THREAD2_NUM;});
    }
    else {
    	tOut->end = time(NULL);		tOut->dTime[6] = (double) (tOut->end-tOut->start);		// compute time
    	printf("[DH-%03d] Time : %f (seconds) \n", idx, tOut->dTime[6]);

		for (int i=0 ; i<CLASS_SIZE ; i++) {
			//oCrypto->DebugOutMain("mc'_i (ciphertext)", cRes[i]->c, idx);
			printf("%02d - ", i);
			oCrypto->DebugDecMain("mc'_i (plaintext)", &(tOut->cRes[i]), idx);
		}
		//oCrypto->TerminatePgm(idx, ucSendBuf, tSend, tRecv);
		short sTrd = oCrypto->TerminatePgm(idx, tRecv);
		PrintResult(tOut->dTime, sTrd);
		tSync->cv.notify_all();		tSync->c1=0;
    }
	ulSync.unlock();
	#endif

	//delete[] ucSendBuf;

	printf("\n<<<  %03d - th Thread END !!!  >>>\n\n", idx);		// temp

	return;
}

void PrintResult(double* ResTime, short sTrd)
{
	// 현재시간 및 시간 결과 출력 (Simple version)
	struct tm *date;
	const time_t t = time(NULL);
	double TotalTime=0;
	int Min, Sec;

	for (int i=0 ; i<7 ; i++)
		TotalTime += ResTime[i];
	date = localtime(&t);

	Min = (int)(TotalTime/60);
	Sec = (int)TotalTime%60;

	printf( "\n[%d/%d/%d %d:%d:%d] %.2f \t %.2f \t %.2f \t %.2f \t %.2f \t %.2f \t %.2f \t %d min %d sec (%.2f) "
			"\t KeySize=%d \t k=%d \t n=%d \t th=%d,%d  \n" ,
		date->tm_year + 1900 , date->tm_mon + 1 , date->tm_mday , date->tm_hour , date->tm_min , date->tm_sec,
		ResTime[0], ResTime[1], ResTime[2], ResTime[3], ResTime[4], ResTime[5], ResTime[6], Min, Sec, TotalTime,
		MOD_SIZE, PARAM_K, DATA_NUM, THREAD1_NUM, sTrd);

	return ;
}

//void SenderTrd(PaillierCrypto *oCrypto, th_t* tSend)
//{
//	oCrypto->Sender(tSend);
//	return;
//}

void ReceiverTrd(PaillierCrypto *oCrypto, thp_t* tRecv)
{
	oCrypto->Receiver(tRecv);
	return;
}

void Initialization(in_t* tIn, out_t* tOut, skle_1_t* tSkle1)
{
	for (int i=0 ; i<CLASS_SIZE ; i++)			tIn->Class[i] = i+1;
	for (int i=0 ; i<DATA_DIMN ; i++)
		#ifdef _DEBUG_INIT_1
		mpz_init(tIn->cQuery[i].c);
		#else
		mpz_init2(tIn->cQuery[i].c, 3*GMP_N_SIZE+1);
		#endif

	for (int i=0 ; i<DATA_NUM ; i++) {
		for (int j=0 ; j<DATA_DIMN ; j++)
			#ifdef _DEBUG_INIT_1
			mpz_init(tIn->cData[i][j].c);
			#else
			mpz_init2(tIn->cData[i][j].c, 3*GMP_N_SIZE+1);
			#endif
		#ifdef _DEBUG_INIT_1
		mpz_init(tIn->cClass[i].c);
		#else
		mpz_init2(tIn->cClass[i].c, 3*GMP_N_SIZE+1);
		#endif
	}

	for (int i=0 ; i<DATA_NUM ; i++) {
		for (int j=0 ; j<DATA_SQUARE_LENGTH ; j++)
			#ifdef _DEBUG_INIT_1
			mpz_init(tOut->cDisB[i][j].c);
			#else
			mpz_init2(tOut->cSbit[i][j].c, 2*GMP_N_SIZE*2);
			#endif
		#ifdef _DEBUG_INIT_1
		mpz_inits(tOut->cDist[i].c, tOut->cK[i].c, NULL);
		#else
		mpz_init2(tOut->cTS[i].c, 2*GMP_N_SIZE*2);
		mpz_init2(tOut->cK[i].c, 2*GMP_N_SIZE*2);
		#endif
	}

	for (int i=0 ; i<THREAD1_NUM ; i++)
		#ifdef _DEBUG_INIT_1
		mpz_init(tOut->cTS[i].c);
		#else
		mpz_init2(tOut->cTS[i].c, 2*GMP_N_SIZE*2);
		#endif
	#ifdef _DEBUG_INIT_1
			mpz_inits(tOut->cS.c, NULL);
	#else
	mpz_init2(tOut->cS.c, 2*GMP_N_SIZE*2);
	#endif

	for (int i=0 ; i<THREAD1_NUM ; i++)
		for (int j=0 ; j<CLASS_SIZE ; j++)
			#ifdef _DEBUG_INIT_1
						mpz_init_set_ui(tOut->cTFre[i][j].c, 1);		// E_cTF[][] = E(0) : 초기화
			#else
			{ 	mpz_init2(tOut->cTFre[i][j].c, 2*GMP_N_SIZE*2);
				mpz_set_ui(tOut->cTFre[i][j].c, 1); 			}
			#endif

	// cTRes[j] = f[j] for j=1~v : result of SCF
	for (int i=0 ; i<CLASS_SIZE ; i++) {
		for (int j=0 ; j<DATA_NUMBER_LENGTH ; j++)
			#ifdef _DEBUG_INIT_1
			mpz_init(tOut->cFreB[i][j].c);
			#else
			mpz_init2(tOut->cFreB[i][j].c, 2*GMP_N_SIZE*2);
			#endif
		#ifdef _DEBUG_INIT_1
		mpz_inits(tOut->cFreq[i].c, tOut->cFK[i].c, tOut->cRes[i].c, NULL);
		#else
		mpz_init2(tOut->cFreq[i].c, 2*GMP_N_SIZE*2);
		mpz_init2(tOut->cFK[i].c, 2*GMP_N_SIZE*2);
		mpz_init2(tOut->cRes[i].c, 2*GMP_N_SIZE);
		#endif
	}

	for (int i=0 ; i<7 ; i++)
		tOut->dTime[i] = 0;

	// 각 thread의 데이터 처리 범위 정하기
	#ifdef _DEBUG_Assert
	assert(DATA_NUM >= THREAD1_NUM);
	#endif

	int iQuo, iRem;
	iQuo = (int)(DATA_NUM / THREAD1_NUM);
	iRem = DATA_NUM % THREAD1_NUM;
	tOut->iRan[0] = 0;
	for (int i=0 ; i<THREAD1_NUM ; i++) {
		tOut->iRan[i+1] = tOut->iRan[i] + iQuo;
		if (i<iRem)
			tOut->iRan[i+1]++;
	}

	#ifdef _DEBUG_Initialization
	std::cout << "[DH] Data range of the 1st Thread : ";
	for (int i=0 ; i<THREAD1_NUM+1 ; i++)
		std::cout << tOut->iRan[i] << " ";
	printf("\n");
	#endif

	#ifdef _DEBUG_Assert
	assert(tOut->iRan[THREAD1_NUM]==DATA_NUM);
	#endif

	// 각 Main thread2의 데이터 처리 범위 정하기
	// THREAD2_NUM = THREAD1_NUM>=CLASS_SIZE?CLASS_SIZE:THREAD1_NUM;
	tOut->iRan2[0] = 0;
	if (THREAD1_NUM >= CLASS_SIZE) {
		for (int i=0 ; i<CLASS_SIZE ; i++)
			tOut->iRan2[i+1] = i+1;
	}
	else {
		iQuo = (int)(CLASS_SIZE / THREAD2_NUM);
		iRem = CLASS_SIZE % THREAD2_NUM;
		for (int i=0 ; i<THREAD2_NUM ; i++) {
			tOut->iRan2[i+1] = tOut->iRan2[i] + iQuo;
			if (i<iRem)
				tOut->iRan2[i+1]++;
		}
	}

	#ifdef _DEBUG_Initialization
	std::cout << "[DH] Data range of the 2nd Thread : ";
	for (int i=0 ; i<THREAD2_NUM+1 ; i++)
		std::cout << tOut->iRan2[i] << " ";
	printf("\n");
	#endif

	#ifdef _DEBUG_Assert
	assert(tOut->iRan2[THREAD2_NUM]==CLASS_SIZE);
	#endif


	// Comparison 함수의 input parameter
	for (int i=0 ; i<DATA_NUMBER_LENGTH ; i++) {
		#ifdef _DEBUG_INIT_1
		mpz_inits(tSkle1->cSb[0][i].c, tSkle1->cSb[1][i].c, NULL);
		#else
		{ mpz_init2(tSkle->cSb[0][i].c, 2*GMP_N_SIZE*2);
		  mpz_init2(tSkle->cSb[1][i].c, 2*GMP_N_SIZE*2);	}
		#endif
	}

	// SkLE의 M, D, A, B, G의 초기화
	#ifdef _DEBUG_INIT_1
	mpz_inits(tSkle1->cM.c, tSkle1->cD.c, tSkle1->cA.c, tSkle1->cB.c, tSkle1->cG.c, NULL);
	#else
	mpz_init2(tSkle1->cM.c, GMP_N_SIZE+1);
	mpz_init2(tSkle1->cD.c, GMP_N_SIZE+1);
	mpz_init2(tSkle1->cA.c, GMP_N_SIZE+1);
	mpz_init2(tSkle1->cB.c, GMP_N_SIZE+1);
	mpz_init2(tSkle1->cG.c, GMP_N_SIZE+1);
	#endif


	return;
}

int main() {
//	vector<thread> PPkNNThreads, SenderThreads, ReceiverThreads;
	vector<thread> PPkNNThreads, ReceiverThreads;
	in_t   	tIn;
	out_t  	tOut;
	skle_1_t 	tSkle1;
	sync_t 	tSync;
//	th_t   	tSend;
	thp_t  	tRecv;
	PaillierCrypto oCrypto;

	Initialization(&tIn, &tOut, &tSkle1);
	tSync.c1 = tSync.c2 = 0;
	for (int i=0 ; i<THREAD1_NUM ; i++)		tRecv.pa[i] = NULL;

	// distribute public key
	oCrypto.SetPubKey();

	// distribute private key for debugging
	oCrypto.SetPrvKey();

	// input dataset(DO->DH), input query(Q->DH)
	oCrypto.inputDatasetQuery(&tIn);

	// generate PPkNN threads and Communication threads
	for (int i=0 ; i<THREAD1_NUM ; i++)
		PPkNNThreads.push_back(thread(PPkNNTrd, (unsigned short)i, &tIn, &tOut, &tSkle1, &oCrypto, &tSync, &tRecv));
		//PPkNNThreads.push_back(thread(PPkNNTrd, &oCrypto, &tSync, &tOut, &tIn, (unsigned short)i, &tRecv, &tSend));

	//SenderThreads.push_back(thread(SenderTrd, &oCrypto, &tSend));
	ReceiverThreads.push_back(thread(ReceiverTrd, &oCrypto, &tRecv));

	// terminate PPkNN threads and Communication threads

	for (int i=0 ; i<THREAD1_NUM ; i++)
		PPkNNThreads[i].join();
	std::cout << std::endl << "<<<  (PPkNNDH) Main Thread TERMINATE !!!  >>>"<< std::endl << std::endl;

	//SenderThreads[0].join();
	//std::cout << std::endl << "<<<  (PPkNNDH) Sending Thread TERMINATE !!!  >>>"<< std::endl << std::endl;
	ReceiverThreads[0].join();
	std::cout << std::endl << "<<<  (PPkNNDH) Receiving Thread TERMINATE !!!  >>>"<< std::endl << std::endl;


	// ************************   PPkNN result   ************************ //

	int iTotal=0;
	for (int i=0 ; i<7 ; i++)
		iTotal += tOut.dTime[i];
	std::cout << std::endl << "************   Running Time   ************"<< std::endl << std::endl;
	std::cout << "1. Squared Distance : \t\t\t\t" 				 << tOut.dTime[0] << std::endl;
	std::cout << "2. Secure Bit-Decomposition : \t\t\t" 		 << tOut.dTime[1] << std::endl;
	std::cout << "3. SkLE_s : \t\t\t\t\t" 						 << tOut.dTime[2] << std::endl;
	std::cout << "4. Class Frequency of Top-k Data (SCF) : \t" << tOut.dTime[3] << std::endl;
	std::cout << "5. Secure Bit-Decomposition for f'_j : \t\t" 	 << tOut.dTime[4] << std::endl;
	std::cout << "6. IPE-FT1 (f'_j) : \t\t\t\t" 				 << tOut.dTime[5] << std::endl;
	std::cout << "7. Computing mc'_j : \t\t\t\t" 				 << tOut.dTime[6] << std::endl;
	std::cout << "*. Total : \t\t\t\t\t" 				 		 << iTotal		  << std::endl;

	// checking the allocated size  of GMP
	#ifdef _DEBUG_Assert
	assert(tIn.   cQuery[0].c->_mp_alloc == 3*GMP_N_SIZE+1);
	assert(tIn. cData[0][0].c->_mp_alloc == 3*GMP_N_SIZE+1);
	assert(tIn.   cClass[0].c->_mp_alloc == 3*GMP_N_SIZE);
	assert(tOut. 	  cTS[0].c->_mp_alloc == 2*GMP_N_SIZE*2);
	assert(tOut.cSbit[0][0].c->_mp_alloc == 2*GMP_N_SIZE*2);
	assert(tOut.    cK[0].c->_mp_alloc == 2*GMP_N_SIZE*2);
	assert(tOut.   cTS[0].c->_mp_alloc == 2*GMP_N_SIZE*2);
	assert(tOut.   	   cS.c->_mp_alloc <= 2*GMP_N_SIZE*2);
	assert(tOut.  cTFre[0][0].c->_mp_alloc == 2*GMP_N_SIZE*2);
	assert(tOut. 	  cFreq[0].c->_mp_alloc <= 2*GMP_N_SIZE*2);
	assert(tOut.cFreB[0][0].c->_mp_alloc <= 2*GMP_N_SIZE*2);
	assert(tOut.   cFK[0].c->_mp_alloc == 2*GMP_N_SIZE*2);
	assert(tOut. 	 cRes[0].c->_mp_alloc == 2*GMP_N_SIZE);
	#endif

	return 0;
}

