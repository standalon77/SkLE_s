//============================================================================
// Name        : PPkNNCSP.cpp
// Author      : PJS
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include "PaillierCrypto.h"
#include <vector>
#include <thread>

using namespace std;

//void PPkNNTrd(PaillierCrypto *oCrypto, unsigned short idx, th_t* tRecv, th_t* tSend)
void PPkNNTrd(PaillierCrypto *oCrypto, unsigned short idx, th_t* tRecv)
{
	std::unique_lock<std::mutex> ulRecv(tRecv->m, std::defer_lock);
	//unsigned char* ucSendBuf = new unsigned char[HED_SIZE+ENC_SIZE];
	unsigned char* ucRecvPtr;

	#ifdef _DEBUG_THREAD
	printf("<<<  %03d - th Thread start  >>>\n", idx);
	#endif

	while(1) {
		ulRecv.lock();
		tRecv->cv.wait(ulRecv, [&] {return !tRecv->q.empty();});

		ucRecvPtr = tRecv->q.front();
		tRecv->q.pop();
		ulRecv.unlock();

		switch(ucRecvPtr[2]) {
		case COM_MUL1  :
			#ifdef _DEBUG_THREAD
			printf("\n<<<  %03d - Sqare Command >>>\n\n", idx);
			#endif
			//oCrypto->SecMul1	 (idx, ucRecvPtr, ucSendBuf, tSend);	break;
			oCrypto->SecMul1	 (idx, ucRecvPtr);						break;
		case COM_MUL2  :
			#ifdef _DEBUG_THREAD
			printf("\n<<<  %03d - Multiplication Command >>>\n\n", idx);
			#endif
			//oCrypto->SecMul2	 (idx, ucRecvPtr, ucSendBuf, tSend);	break;
			oCrypto->SecMul2	 (idx, ucRecvPtr);						break;
		case COM_LSB   :
			#ifdef _DEBUG_THREAD
			printf("\n<<<  %03d - Encrypted LSB Command >>>\n\n", idx);
			#endif
			//oCrypto->EncryptedLSB(idx, ucRecvPtr, ucSendBuf, tSend);	break;
			oCrypto->EncryptedLSB(idx, ucRecvPtr);						break;
		case COM_SVR   :
			#ifdef _DEBUG_THREAD
			printf("\n<<<  %03d - SVR Command >>>\n\n", idx);
			#endif
			//oCrypto->SVR		 (idx, ucRecvPtr, ucSendBuf, tSend);	break;
			oCrypto->SVR		 (idx, ucRecvPtr);						break;
		case COM_SCI   :
			#ifdef _DEBUG_THREAD
			printf("\n<<<  %03d - SCI Command >>>\n\n", idx);
			#endif
			//oCrypto->SVR		 (idx, ucRecvPtr, ucSendBuf, tSend);	break;
			oCrypto->SCI		 (idx, ucRecvPtr);						break;
		case COM_SZP   :
			#ifdef _DEBUG_THREAD
			printf("\n<<<  %03d - SZP Command >>>\n\n", idx);
			#endif
			//oCrypto->SVR		 (idx, ucRecvPtr, ucSendBuf, tSend);	break;
			oCrypto->SCI		 (idx, ucRecvPtr);						break;
		case COM_SCF :
			#ifdef _DEBUG_THREAD
			printf("\n<<<  %03d - SCF Command >>>\n\n", idx);
			#endif
			//oCrypto->SCF	 (idx, ucRecvPtr, ucSendBuf, tSend);break;
			oCrypto->SCF		 (idx, ucRecvPtr);						break;
		case COM_TERM :
			#ifdef _DEBUG_THREAD
			printf("\n<<<  %03d - TERMINATE Command >>>\n\n", idx);
			#endif
			//oCrypto->TerminatePgm(idx, ucRecvPtr, ucSendBuf, tSend);
			oCrypto->TerminatePgm(idx, ucRecvPtr);

			//delete[] ucSendBuf;
			printf("\n<<<  %03d - th Thread END !!!  >>>\n\n", idx);
			return;
		default:
			short sIdx = (ucRecvPtr[1]<<8) + ucRecvPtr[0];
			oCrypto->DebugComMain("RecvBuf Error Msg (Hex)\t", ucRecvPtr, HED_SIZE+2*ENC_SIZE, idx, sIdx);
			assert(0);
		}
	}

	return;
}

//void SenderTrd(PaillierCrypto *oCrypto, th_t* tSend)
//{
//	oCrypto->Sender(tSend);
//	return;
//}

void ReceiverTrd(PaillierCrypto *oCrypto, th_t* tRecv)
{
	oCrypto->Receiver(tRecv);
	return;
}

int main() { //
//	th_t tSend, tRecv;
//	vector<thread> PPkNNThreads, SenderThreads, ReceiverThreads;
	th_t tRecv;
	vector<thread> PPkNNThreads, ReceiverThreads;
	PaillierCrypto oCrypto(MOD_SIZE);

	// distribute public key
	oCrypto.distributePubKey();

	// distribute private key for debugging
	oCrypto.distributePrvKey();

	// generate PPkNN threads and Communication threads
	for (int i=0 ; i<NUM_PPkNN_THREAD ; i++)
		PPkNNThreads.push_back(thread(PPkNNTrd, &oCrypto, (unsigned short)i, &tRecv));
		//PPkNNThreads.push_back(thread(PPkNNTrd, &oCrypto, (unsigned short)i, &tRecv, &tSend));

	//SenderThreads.push_back(thread(SenderTrd, &oCrypto, &tSend));
	ReceiverThreads.push_back(thread(ReceiverTrd, &oCrypto, &tRecv));

	// terminate PPkNN threads and Communication threads

	for (int i=0 ; i<NUM_PPkNN_THREAD ; i++)
		PPkNNThreads[i].join();
	std::cout << std::endl << "<<<  (PPkNNCSP) Main Thread TERMINATE !!!  >>>"<< std::endl << std::endl;

	//SenderThreads[0].join();
	//std::cout << std::endl << "<<<  (PPkNNCSP) Sending Thread TERMINATE !!!  >>>"<< std::endl << std::endl;
	ReceiverThreads[0].join();
	std::cout << std::endl << "<<<  (PPkNNCSP) Receiving Thread TERMINATE !!!  >>>"<< std::endl << std::endl;

	return 0;
}

