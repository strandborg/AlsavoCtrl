// AlsavoCtrl.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include "stdio.h"
#include "stdlib.h"
#include "stdint.h"
#include "time.h"
#include "MD5.h"
#include <string>
#include <vector>
#include <atomic>
#include <thread>
#include <queue>
#include <mutex>
#include <map>
#include <functional>
#include <set>
#include <time.h>
#include <memory.h>
#include <numeric>
#include <chrono>
#include "CLI11.hpp"
#include "loguru.hpp"

#ifdef _MSC_VER
#include "winsock2.h"
#include "WS2tcpip.h"
#pragma comment(lib, "ws2_32.lib")
#else
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#define htonll(x) ((((uint64_t)htonl(x)) << 32) + htonl((x) >> 32))
#define HIBYTE(w)           ((unsigned char)((uint32_t)(w) >> 8))
#endif

static std::string s_ServerAddr{"47.254.157.150"};
static int s_ServerPort{51192};
static std::string s_SerialNumber;
static std::string s_Password;
static bool s_Listen = false;
static int s_ConfigIndex = -1;
static int s_ConfigValue = -1;
#pragma pack(1)
struct PacketHeader
{
	char hdr;
	char pad;
	uint16_t seq;
	uint32_t csid;
	uint32_t dsid;
	uint16_t cmd;
	uint16_t payloadLength;
	bool isReply() const { return (hdr & 2) == 0; }
	PacketHeader(char _hdr, uint16_t _seq, uint32_t _csid, uint32_t _dsid, uint16_t _cmd, uint16_t _payloadLength)
		: hdr(_hdr), pad(0), seq(_seq), csid(_csid), dsid(_dsid), cmd(htons(_cmd)), payloadLength(htons(_payloadLength))
	{}
};

struct Timestamp
{
	uint16_t year;
	char month;
	char day;
	char hour;
	char min;
	char sec;
	char tz;

	void Now()
	{
		time_t timer;
		time(&timer);
		struct tm gmt;
#ifdef _MSC_VER
		gmtime_s(&gmt, &timer);
#else
		gmtime_r(&timer, &gmt);
#endif
		year = gmt.tm_year + 1900;
		month = gmt.tm_mon + 1;
		day = gmt.tm_mday;
		hour = gmt.tm_hour;
		min = gmt.tm_min;
		sec = gmt.tm_sec;
		tz = 2; // TODO
		year = htons(year);
	}
	Timestamp()
	{
		Now();
	}
};

struct AuthIntro
{
	PacketHeader hdr;
	char act1, act2, act3, act4;
	uint32_t clientToken;
	uint64_t pumpSerial;
	uint32_t _uuid[4];
	Timestamp timestamp;

	AuthIntro(uint32_t clientToken, uint64_t serialInv)
		: hdr(0x32, 0, 0, 0, 0xf2, 0x28)
		, act1(1), act2(1), act3(2), act4(0)
		, clientToken(clientToken)
		, pumpSerial(serialInv)
		, _uuid { 0xffffffff, 0xd3e2eeac, 0, 0x6afdc755}
		, timestamp()
	{}
};

struct AuthChallenge
{
	PacketHeader hdr;
	char act1, act2, act3, act4;
	uint32_t serverToken;
};

struct AuthResponse
{
	PacketHeader hdr;
	char act1, act2, act3, act4;

	unsigned char response[16];
	Timestamp timestamp;
	AuthResponse(uint32_t csid, uint32_t dsid, unsigned char* resp)
		: hdr(0x32, 0, csid, dsid, 0xf2, 0x1c)
		, act1(4), act2(0), act3(0), act4(3)
		, timestamp()
	{
		memcpy(response, resp, 16);
	}
};

struct StatusQuery
{
	PacketHeader hdr;
	char act[8];
	uint16_t statsOrConfig;
	uint16_t zeroed;
	StatusQuery(uint16_t seq, uint32_t csid, uint32_t dsid, bool queryConfigs)
		: hdr(0x30, (char)seq, csid, dsid, 0xf4, 0xc)
		, act{ 0x0b, 0x01, 0, 0, 0, 2, 0, 0x2e }
		, statsOrConfig(htons(queryConfigs ? 2 : 1))
		, zeroed(0)
	{}
};

struct ParamBlock
{
	uint16_t startIdx;
	uint16_t numParams;
	int16_t payload[1];
};

struct QueryObject
{
	uint32_t objectType;
	uint16_t statsOrConfig; // Stats = 1, config = 2
	uint16_t dataSize;
	ParamBlock paramBlock;
};

struct StatusResponse
{
	PacketHeader hdr;
	char act; // 8
	char numQueries;
	uint16_t pad;
	QueryObject payload[1]; // [numQueries], tightly packed
};


static void printPacket(char* pkt, int len)
{
	PacketHeader* hdr = (PacketHeader*)pkt;
	uint32_t action = *(uint32_t*)(pkt + sizeof(PacketHeader));
	printf("Dbg: packetlen = %d payloadLen = %d, action=%x\n", len, ntohs(hdr->payloadLength), ntohl(action));

	for (int i = sizeof(PacketHeader); i < len; ++i)
	{
		printf("%02hhx ", pkt[i]);
		if ((i+1-sizeof(PacketHeader)) % 16 == 0)
			printf("\n");
	}
	printf("\n");

}

class AlsavoSession
{
public:
	AlsavoSession(const std::string serial, const std::string passwd)
		: m_SerialNo(serial), m_Password(passwd), m_LastPacketRcvTime(std::chrono::system_clock::now())
	{
#ifdef _MSC_VER
		WSADATA wsadata;
		WSAStartup(MAKEWORD(2, 2), &wsadata);
#endif
		srand((uint32_t)time(NULL));

		MD5_CTX ctx;
		MD5_Init(&ctx);
		MD5_Update(&ctx, (char*)m_Password.c_str(), (unsigned int)m_Password.length());
		MD5_Final(m_HashedPW, &ctx);

		memset(&m_DestAddr, 0, sizeof(sockaddr_in));
		m_DestAddr.sin_family = AF_INET;
		m_DestAddr.sin_port = htons(s_ServerPort);
		inet_pton(AF_INET, s_ServerAddr.c_str(), &m_DestAddr.sin_addr);
		int64_t s = atoll(serial.c_str());
		m_SerialQ = htonll(s);
	}

	~AlsavoSession()
	{
		if (m_WorkerThread.joinable())
		{
			m_Dying = true;
			m_WorkerThread.join();
		}
#ifdef _MSC_VER
		WSACleanup();
#endif
	}

	void SendPacket(const std::vector<unsigned char> &payload, uint16_t cmd = 0xf4)
	{
		std::vector<unsigned char> outBuf;
		outBuf.resize(sizeof(PacketHeader) + payload.size());
		PacketHeader hdr(0x32, 0, m_CSID, m_DSID, cmd, (uint16_t)payload.size());
		memcpy(outBuf.data(), &hdr, sizeof(PacketHeader));
		memcpy(outBuf.data() + sizeof(PacketHeader), payload.data(), (uint16_t)payload.size());
		std::lock_guard<std::recursive_mutex> lock(m_QueueLock);
		m_OutQueue.push_back(std::move(outBuf));
	}
	void SendReply(const std::vector<unsigned char>& payload, uint16_t seq, uint16_t cmd = 0xf4)
	{
		std::vector<unsigned char> outBuf;
		outBuf.resize(sizeof(PacketHeader) + payload.size());
		PacketHeader hdr(0x30, seq, m_CSID, m_DSID, cmd, (uint16_t)payload.size());
		memcpy(outBuf.data(), &hdr, sizeof(PacketHeader));
		memcpy(outBuf.data() + sizeof(PacketHeader), payload.data(), (uint16_t)payload.size());
		std::lock_guard<std::recursive_mutex> lock(m_QueueLock);
		sendto(m_Sock, (char *)outBuf.data(), (int)outBuf.size(), 0, (sockaddr*)&m_DestAddr, sizeof(m_DestAddr));
	}

private:
	int RecvWithTimeout(char* rcvBuf, int bufSize, int timeoutMS)
	{
#ifdef _MSC_VER
		TIMEVAL timeout;
#else
		struct timeval timeout;
#endif
		timeout.tv_sec = 0;
		timeout.tv_usec = timeoutMS * 1000;
		fd_set readSet;
		FD_ZERO(&readSet);
		FD_SET(m_Sock, &readSet);
		int act = select(FD_SETSIZE, &readSet, NULL, NULL, &timeout);
		if (act <= 0)
			return 0;

		sockaddr_in rcvAddr;
		int rcvLen = sizeof(sockaddr_in);
		int bytesReceived = recvfrom(m_Sock, rcvBuf, bufSize, 0, (sockaddr*)&rcvAddr, (socklen_t*)&rcvLen);
		return bytesReceived;
	}
public:
	bool Connect()
	{
		m_IsConnected = false;
		m_NextSeq = 0;
		m_Dying = false;
		m_OutQueue.clear();

		if (m_Sock != 0)
		{
#ifdef _MSC_VER
			closesocket(m_Sock);
#else
			close(m_Sock);
#endif
			m_Sock = 0;
		}
		m_ClientToken = rand() | (rand() << 16);
		m_Sock = socket(AF_INET, SOCK_DGRAM, 0);

		char rcvBuf[512];

		LOG_F(INFO, "Connecting to %s:%d...", s_ServerAddr.c_str(), s_ServerPort);

		AuthIntro intro(m_ClientToken, m_SerialQ);
		sendto(m_Sock, (const char*)&intro, 56, 0, (sockaddr*)&m_DestAddr, sizeof(m_DestAddr));

		int bytesReceived = RecvWithTimeout(rcvBuf, sizeof(rcvBuf), 2000);

		if (bytesReceived == 0)
		{
			LOG_F(ERROR, "Server not responding, disconnecting");
			Disconnect();
			return false;
		}

		AuthChallenge* challenge = (AuthChallenge*)rcvBuf;

		if (!(challenge->act1 == 3 && challenge->act2 == 0 && challenge->act3 == 0 && challenge->act4 == 0))
		{
			LOG_F(ERROR, "Invalid auth challenge packet (pump offline?), disconnecting");
			Disconnect();
			return false;
		}

		m_CSID = challenge->hdr.csid;
		m_DSID = challenge->hdr.dsid;
		m_ServerToken = challenge->serverToken;

		LOG_F(INFO, "Received handshake, CSID=%08X, DSID=%08X, server token %08X", m_CSID, m_DSID, m_ServerToken);

		MD5_CTX ctx;

		MD5_Init(&ctx);
		MD5_Update(&ctx, &m_ClientToken, 4);
		MD5_Update(&ctx, &m_ServerToken, 4);
		MD5_Update(&ctx, m_HashedPW, 16);

		unsigned char respdata[16];
		MD5_Final(respdata, &ctx);

		AuthResponse resp(m_CSID, m_DSID, respdata);
		sendto(m_Sock, (const char*)&resp, sizeof(resp), 0, (sockaddr*)&m_DestAddr, sizeof(m_DestAddr));

		bytesReceived = RecvWithTimeout(rcvBuf, sizeof(rcvBuf), 2000);

		if (bytesReceived == 0)
		{
			LOG_F(ERROR, "Server not responding to auth response, disconnecting");
			Disconnect();
			return false;
		}

		uint32_t act = *(uint32_t*)(&rcvBuf[sizeof(PacketHeader)]);
		if (act != 0x00000005)
		{
			LOG_F(ERROR, "Server returned error in auth, disconnecting");
			Disconnect();
			return false;

		}
		m_IsConnected = true;
		m_LastPacketRcvTime = std::chrono::system_clock::now();

		m_WorkerThread = std::thread(&AlsavoSession::ThreadProc, this);

		LOG_F(INFO, "Connection complete.");

		if (s_ConfigIndex != -1 && s_ConfigValue != -1)
		{
			SetConfig(s_ConfigIndex, s_ConfigValue);
		}

		// These packets seem to make the heat pump send periodic updates, no idea which one of these does it
		SendPacket({ 8, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0 });

        SendPacket({ 8, 1, 0, 0, 0, 2, 0, 0x0c, 0, 7, 0, 4, 0, 1, 0, 0 });

		SendPacket({ 8, 3, 0, 0, 0, 1, 0, 7, 0, 2, 0, 0, 0, 1, 0, 3, 0, 0xc, 0, 0, 0, 1, 0, 3, 0, 0x64, 0, 0});

		SendPacket({ 8, 1, 0, 0, 0, 9, 0, 1, 0, 1, 0, 0 });

		SendPacket({ 0x08, 0x13, 0x00, 0x00,
0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x64, 0x00, 0x00,
0x00, 0x01, 0x00, 0x03, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x03, 0x00, 0x00,
0x00, 0x01, 0x00, 0x04, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01, 0x00, 0x05, 0x00, 0x01, 0x00, 0x00,
0x00, 0x01, 0x00, 0x05, 0x00, 0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x06, 0x00, 0x01, 0x00, 0x00,
0x00, 0x01, 0x00, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x01, 0x00, 0x00,
0x00, 0x01, 0x00, 0x05, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x08, 0x00, 0x00,
0x00, 0x01, 0x00, 0x03, 0x00, 0x09, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x04, 0x00, 0x00,
0x00, 0x01, 0x00, 0x03, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x03, 0x00, 0x06, 0x00, 0x00,
0x00, 0x01, 0x00, 0x07, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x03, 0x00, 0x00,
0x00, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00
			});

		SendPacket({ 8, 1, 0, 0, 0, 2, 0, 0x2e, 0xff, 0xff, 0, 0 });

		SendPacket({ 8, 1, 0, 0, 0, 1, 0, 3, 0, 0xc, 0, 0 });

		SendPacket({ 8, 1, 0, 0, 0, 1, 0, 5, 0, 3, 0, 0 });

		SendPacket({ 8, 1, 0, 0, 0, 1, 0, 3, 0, 3, 0, 0 });

//		QueryAll();

		return true;
	}

	void Disconnect()
	{
		LOG_F(INFO, "Disconnecting.");
		m_Dying = true;
		m_IsConnected = false;
		if (m_WorkerThread.joinable() && std::this_thread::get_id() != m_WorkerThread.get_id())
			m_WorkerThread.join();
		if (m_Sock != 0)
		{
#ifdef _MSC_VER
			closesocket(m_Sock);
#else
			close(m_Sock);
#endif
			m_Sock = 0;
		}
	}

	void SetConfig(int16_t idx, int16_t val)
	{
		unsigned char idxH = HIBYTE(idx);
		unsigned char idxL = idx & 0xff;
		unsigned char valH = HIBYTE(val);
		unsigned char valL = val & 0xff;
		SendPacket({9, 1, 0, 0, 0, 2, 0, 0x2e, 0, 2, 0, 0x4, idxH, idxL, valH, valL });
	}

	void QueryAll()
	{
		SendPacket({8, 1, 0, 0, 0, 2, 0, 0x2e, 0xff, 0xff, 0, 0});
		m_LastConfigReqTime = std::chrono::system_clock::now();
	}

	void CheckAlive()
	{
		if (isConnected())
		{
			auto now = std::chrono::system_clock::now();
			auto diff = std::chrono::duration<double>(now - m_LastPacketRcvTime.load());
			if (diff.count() > 6.0)
			{
//				LOG_F(INFO, "No packets received in 6 seconds, sending keepalive query packet...");
				// Send a keepalive packet
//				SendPacket({ 8, 1, 0, 0, 0, 1, 0, 1, 0, 1, 0, 0 });
				QueryAll();
			}
			if (diff.count() > 20.0)
			{
				LOG_F(ERROR, "Connection timed out, disconnecting.");
				Disconnect();
			}
			if (std::chrono::duration<double>(now - m_LastConfigReqTime).count() > 30.0)
				QueryAll();
		}

		if (!isConnected())
		{
			Disconnect();
			Connect();
		}

	}

	bool isConnected() { return m_IsConnected; }

	void AddHandler(uint32_t action, std::function<void(const std::vector<unsigned char>&, int)> func)
	{
		std::lock_guard<std::recursive_mutex> lock(m_QueueLock);
		m_Handlers.insert(std::make_pair(action, func));
	}

	void ClearHandler(uint32_t action)
	{
		std::lock_guard<std::recursive_mutex> lock(m_QueueLock);
		m_Handlers.erase(action);
	}

private:

	std::recursive_mutex m_QueueLock;
	std::deque<std::vector<unsigned char> > m_OutQueue;

	std::map<char, std::function<void(const std::vector<unsigned char> &, int)> > m_Handlers;

	std::atomic<bool> m_Dying;
	std::thread m_WorkerThread;
	int16_t m_LastReplySeq = -1;
	void ThreadProc()
	{
		int numRetries = 0;
		bool dontRetryYet = false;
		while (!m_Dying.load())
		{
			int16_t lastSentSeq = 0;
			if(!dontRetryYet)
			{
				std::lock_guard<std::recursive_mutex> lock(m_QueueLock);
				if (!m_OutQueue.empty())
				{
					std::vector<unsigned char> &outBuf = m_OutQueue.front();
					PacketHeader* hdr = (PacketHeader*)outBuf.data();
					hdr->seq = m_NextSeq;
					lastSentSeq = m_NextSeq;
					numRetries++;
					uint32_t action = *(uint32_t*)(outBuf.data() + sizeof(PacketHeader));
//					printf("Sending seq %d, retry %d action: %08x\n", m_NextSeq, numRetries, ntohl(action));
					sendto(m_Sock, (char *)outBuf.data(), (int)outBuf.size(), 0, (sockaddr*)&m_DestAddr, sizeof(m_DestAddr));
				}
			}
			dontRetryYet = false;
#ifdef _MSC_VER
			TIMEVAL timeout;
#else
			struct timeval timeout;
#endif
			timeout.tv_sec = 0;
			timeout.tv_usec = m_TimeoutMS * 1000;
			fd_set readSet;
			FD_ZERO(&readSet);
			FD_SET(m_Sock, &readSet);
			int act = select(FD_SETSIZE, &readSet, NULL, NULL, &timeout);
			if (act > 0)
			{
				std::vector<unsigned char> rcvBuf;
				rcvBuf.resize(1024);
				sockaddr_in rcvAddr;
				int rcvLen = sizeof(sockaddr_in);

				int bytesReceived = recvfrom(m_Sock, (char *)rcvBuf.data(), (int)rcvBuf.size(), 0, (sockaddr*)&rcvAddr, (socklen_t *)&rcvLen);

				if (bytesReceived > 0)
				{
					m_LastPacketRcvTime = std::chrono::system_clock::now();
					std::lock_guard<std::recursive_mutex> lock(m_QueueLock);
					PacketHeader* hdr = (PacketHeader *)rcvBuf.data();
					if (hdr->isReply())
					{
//						printf("Got reply seq %d\n", hdr->seq);
						if (hdr->seq == lastSentSeq)
						{
							// Got reply, can discard the queue head
							if (!m_OutQueue.empty())
							{
								m_OutQueue.pop_front();
								m_NextSeq++;
							}
							numRetries = 0;
						}
					}
					else
						dontRetryYet = true;

					char action = 0;
					if (bytesReceived >= sizeof(PacketHeader) + 4)
					{
						action = *(char*)(rcvBuf.data() + sizeof(PacketHeader));
					}
					// Check for connection reset
					if (action == 0x7)
					{
						// Connection reset
						LOG_F(ERROR, "Received connection reset packet, disconnecting.");
						Disconnect();
						return;
					}


					auto itr = m_Handlers.find(action);
					if (itr == m_Handlers.end())
						itr = m_Handlers.find(0);
					if (itr != m_Handlers.end())
						itr->second(rcvBuf, bytesReceived);

				}

			}
			if (numRetries > m_MaxRetries)
			{
				LOG_F(ERROR, "No reply received after %d retries, disconnecting", numRetries);
				Disconnect();
				return;
			}



		}
	}
#ifdef _MSC_VER
	SOCKET m_Sock{ 0 };
#else
	int m_Sock{ 0 };
#endif
	bool m_IsConnected = false;

	sockaddr_in m_DestAddr;

	std::string m_SerialNo;
	uint64_t m_SerialQ;
	std::string m_Password;
	unsigned char m_HashedPW[16];

	uint32_t m_ClientToken = 0;
	uint32_t m_ServerToken = 0;

	uint32_t m_CSID = 0;
	uint32_t m_DSID = 0;

	int16_t m_NextSeq = 0;

	int m_MaxRetries = 3;
	int m_TimeoutMS = 500;

	std::atomic<std::chrono::time_point<std::chrono::system_clock>> m_LastPacketRcvTime;
	std::chrono::time_point<std::chrono::system_clock> m_LastConfigReqTime;

};



class Runner
{
public:
	AlsavoSession m_Session;

	std::set<int> m_TemperatureStatusIndices{ 16, 17, 18, 19, 20, 21, 23, 24, 55, 56 };

	Runner()
		: m_Session	(s_SerialNumber, s_Password)
	{
	}

	void HandleParamBlock(ParamBlock* block, bool isConfigs)
	{
		int startIdx = ntohs(block->startIdx);
		int numParams = ntohs(block->numParams);

		for (int i = startIdx; i < startIdx + numParams; ++i)
		{
			int16_t valInt = ntohs(block->payload[i - startIdx]);
			if (valInt == -21931)
				continue;
			if(isConfigs)
			{
				printf("{\"type\":\"config\", \"index\":%d, \"value\":%d}\n", i, valInt);
			}
			else
			{
				if (m_TemperatureStatusIndices.find(i) != m_TemperatureStatusIndices.end())
				{
					float fval = ((float)valInt) / 10.0f;
					printf("{\"type\":\"status\", \"index\":%d, \"value\":%.1f}\n", i, fval);
				}
				else
					printf("{\"type\":\"status\", \"index\":%d, \"value\":%d}\n", i, valInt);
			}
		}

	}

	void ParseObject(QueryObject* obj)
	{
		if (obj->objectType == 0x2e000200)
		{
			// Param block
			auto type = ntohs(obj->statsOrConfig);
			if(type == 1 || type == 2)
				HandleParamBlock(&obj->paramBlock, type == 2);

		}
	}

	void DefaultHandler(std::vector<unsigned char> packet, int byteCount)
	{
		PacketHeader* hdr = (PacketHeader*)packet.data();
		unsigned char *payload = &packet[sizeof(PacketHeader)];
		auto cmd = payload[0];

		if (cmd == 0x0b || cmd == 0x08)
		{
			// Status packet, parse objects
			auto objectCount = payload[1];
			QueryObject* obj = (QueryObject *)&payload[4];
			for (int i = 0; i < objectCount; ++i)
			{
				ParseObject(obj);
				int16_t dataSize = ntohs(obj->dataSize);
				obj = (QueryObject*)(((char *)obj)+dataSize + 8);
			}

			if(cmd == 0x0b)
				m_Session.SendReply({ 0x0b, 0x01, 0, 0, 0, 2, 0, 0x2e, 0, payload[9], 0, 0 }, hdr->seq);
		}

		if (cmd == 0x09 && !s_Listen)
		{
			// Quit once we get the answer to param setting command and we're not in listening mode
			exit(0);
		}

		//		printf("Default handler: ");
//		printPacket((char*)packet.data(), byteCount);

	}


	int main()
	{
		m_Session.AddHandler(0, [this](const std::vector<unsigned char> &packet, int byteCount){	DefaultHandler(packet, byteCount);	});

		m_Session.Connect(); 

		while(1)
		{
#ifdef _MSC_VER
			Sleep(1000);
#else
			sleep(1);
#endif
			m_Session.CheckAlive();
		}
		return 0;
	}

};

int main(int argc, char **argv)
{
	CLI::App app{"Alsavo heat pump control"};
	std::string logFile{};

	app.add_option("-s,--serial", s_SerialNumber, "Serial number string of the heat pump")->required();
	app.add_option("-l,--password", s_Password, "Password")->required();
	app.add_option("-a,--address", s_ServerAddr, "Override server address, defaults to 47.254.157.150");
	app.add_option("-p,--port", s_ServerPort, "Override server port, default 51194");
	app.add_flag("--listen", s_Listen, "Keep listening for status updates");
	app.add_option("-g,--logfile", logFile, "Write log to file");
	app.add_option("conf_idx", s_ConfigIndex, "Config index to write");
	app.add_option("value", s_ConfigValue, "Value to write");

	CLI11_PARSE(app, argc, argv);

	loguru::init(argc, argv);

	if (!logFile.empty())
		loguru::add_file(logFile.c_str(), loguru::Truncate, loguru::Verbosity_INFO);

	Runner r;
	return r.main();
}