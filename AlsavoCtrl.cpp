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
#include <math.h>

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
static bool s_Silence = false;
static bool s_JSONOutput = false;
static int s_ConfigIndex = -1;
static int s_ConfigValue = -1;
static std::string s_verbosity;

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
	enum class ConnectionStatus
	{
		Disconnected = 0,
		Connected = 1
	};

	ConnectionStatus GetConnectionStatus() const { return m_ConnectionStatus; }

	AlsavoSession()
		: m_LastPacketRcvTime(std::chrono::system_clock::now())
		, m_ConnectionStatus(ConnectionStatus::Disconnected)
	{
#ifdef _MSC_VER
		WSADATA wsadata;
		WSAStartup(MAKEWORD(2, 2), &wsadata);
#endif
	}

	~AlsavoSession()
	{
#ifdef _MSC_VER
		WSACleanup();
#endif
	}

	typedef std::function<void(const std::vector<unsigned char>&, int)> PacketResponseCB;

	void SendPacket(const std::vector<unsigned char> &payload, PacketResponseCB onResponse, uint16_t cmd = 0xf4)
	{
		std::vector<unsigned char> outBuf;
		outBuf.resize(sizeof(PacketHeader) + payload.size());
		PacketHeader hdr(0x32, 0, m_CSID, m_DSID, cmd, (uint16_t)payload.size());
		memcpy(outBuf.data(), &hdr, sizeof(PacketHeader));
		memcpy(outBuf.data() + sizeof(PacketHeader), payload.data(), (uint16_t)payload.size());
		m_OutQueue.emplace_back(std::move(outBuf), onResponse);
	}

	void SendPacketNow(const std::vector<unsigned char>& payload, uint16_t seq, bool isReply = false, uint16_t cmd = 0xf4)
	{
		std::vector<unsigned char> outBuf;
		outBuf.resize(sizeof(PacketHeader) + payload.size());
		PacketHeader hdr(isReply ? 0x30 : 0x32, seq, m_CSID, m_DSID, cmd, (uint16_t)payload.size());
		memcpy(outBuf.data(), &hdr, sizeof(PacketHeader));
		memcpy(outBuf.data() + sizeof(PacketHeader), payload.data(), (uint16_t)payload.size());
		sendto(m_Sock, (char*)outBuf.data(), (int)outBuf.size(), 0, (sockaddr*)&m_DestAddr, sizeof(m_DestAddr));
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
	void Connect(const std::string serverIP, int16_t serverPort, const std::string &serial, const std::string &passwd)
	{
		m_SerialNo = serial;
		m_Password = passwd;

		srand((uint32_t)time(NULL));

		MD5_CTX ctx;
		MD5_Init(&ctx);
		MD5_Update(&ctx, (char*)m_Password.c_str(), (unsigned int)m_Password.length());
		MD5_Final(m_HashedPW, &ctx);

		memset(&m_DestAddr, 0, sizeof(sockaddr_in));
		m_DestAddr.sin_family = AF_INET;
		m_DestAddr.sin_port = htons(serverPort);
		inet_pton(AF_INET, serverIP.c_str(), &m_DestAddr.sin_addr);
		int64_t s = atoll(serial.c_str());
		m_SerialQ = htonll(s);

		Disconnect();

		m_ClientToken = rand() | (rand() << 16);
		m_Sock = socket(AF_INET, SOCK_DGRAM, 0);

		char rcvBuf[512];

		LOG_F(INFO, "Connecting to %s:%d...", serverIP.c_str(), serverPort);

		AuthIntro intro(m_ClientToken, m_SerialQ);
		sendto(m_Sock, (const char*)&intro, 56, 0, (sockaddr*)&m_DestAddr, sizeof(m_DestAddr));
		
		int bytesReceived = RecvWithTimeout(rcvBuf, sizeof(rcvBuf), 2000);

		if (bytesReceived == 0)
		{
			LOG_F(ERROR, "Server not responding, disconnecting");
			Disconnect();
			return;
		}

		AuthChallenge* challenge = (AuthChallenge*)rcvBuf;

		if (!(challenge->act1 == 3 && challenge->act2 == 0 && challenge->act3 == 0 && challenge->act4 == 0))
		{
			LOG_F(ERROR, "Invalid auth challenge packet (pump offline?), disconnecting");
			Disconnect();
			return;
		}

		m_CSID = challenge->hdr.csid;
		m_DSID = challenge->hdr.dsid;
		m_ServerToken = challenge->serverToken;

		LOG_F(INFO, "Received handshake, CSID=%08X, DSID=%08X, server token %08X", m_CSID, m_DSID, m_ServerToken);

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
			return;
		}

		uint32_t act = *(uint32_t*)(&rcvBuf[sizeof(PacketHeader)]);
		if (act != 0x00000005)
		{
			LOG_F(ERROR, "Server returned error in auth, disconnecting");
			Disconnect();
			return;

		}
		m_LastPacketRcvTime = std::chrono::system_clock::now();
		UpdateConnectionStatus(ConnectionStatus::Connected);

		LOG_F(INFO, "Connection complete.");

		return;
	}

	void Disconnect()
	{
		LOG_F(INFO, "Disconnecting.");
		if (m_ConnectionStatus == ConnectionStatus::Connected)
		{
			SendPacketNow({ 0x07, 0, 0, 0 }, 0, false, 0xf3);
		}
		UpdateConnectionStatus(ConnectionStatus::Disconnected);
		m_NextSeq = 0;
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
	}

	void SetConfig(int16_t idx, int16_t val, PacketResponseCB onComplete)
	{
		unsigned char idxH = HIBYTE(idx);
		unsigned char idxL = idx & 0xff;
		unsigned char valH = HIBYTE(val);
		unsigned char valL = val & 0xff;
		SendPacket({9, 1, 0, 0, 0, 2, 0, 0x2e, 0, 2, 0, 0x4, idxH, idxL, valH, valL }, onComplete);
	}

	void QueryAll(PacketResponseCB onComplete)
	{
		SendPacket({8, 1, 0, 0, 0, 2, 0, 0x2e, 0xff, 0xff, 0, 0}, onComplete);
		m_LastConfigReqTime = std::chrono::system_clock::now();
	}

	typedef std::function<void(ConnectionStatus newStatus, ConnectionStatus oldStatus)> ConnectionStatusCB;

	void SetConnectionStatusHandler(ConnectionStatusCB cb)
	{
		m_ConnStatusCB = cb;
	}

	typedef std::function<void(const std::vector<unsigned char>&, int)> PacketHandlerCB;

	void SetStatusPacketHandler(PacketHandlerCB func)
	{
		m_StatusHandler = func;
	}

private:

	ConnectionStatus m_ConnectionStatus;
	struct PacketQueueItem
	{
		PacketQueueItem(std::vector<unsigned char> pkt, PacketResponseCB cb)
			: packetPayload(pkt)
			, onResponse(cb)
			, m_LastSendTime{}
			, numRetries(0)
		{
		}
		std::vector<unsigned char> packetPayload;
		PacketResponseCB onResponse;
		std::chrono::time_point<std::chrono::system_clock> m_LastSendTime;
		int numRetries;
	};

	ConnectionStatusCB m_ConnStatusCB;

	void UpdateConnectionStatus(ConnectionStatus newStatus)
	{
		auto oldStat = m_ConnectionStatus;
		m_ConnectionStatus = newStatus;
		if (m_ConnStatusCB && oldStat != newStatus)
			m_ConnStatusCB(newStatus, oldStat);
	}


	std::deque<PacketQueueItem> m_OutQueue;

	PacketHandlerCB m_StatusHandler;

	std::chrono::duration<float, std::milli> m_PacketTimeout {1000.0f};

public:
	void Pump()
	{
		if (!m_OutQueue.empty())
		{
			auto& outPkt = m_OutQueue.front();
			auto now = std::chrono::system_clock::now();
			if (now - outPkt.m_LastSendTime > m_PacketTimeout)
			{
				// Timed out (or hasn't even been sent yet), re-send
				if (outPkt.numRetries > m_MaxRetries)
				{
					LOG_F(ERROR, "No reply received after %d retries, disconnecting", m_MaxRetries);
					Disconnect();
					return;
				}

				std::vector<unsigned char>& outBuf = outPkt.packetPayload;
				PacketHeader* hdr = (PacketHeader*)outBuf.data();
				hdr->seq = m_NextSeq;
				outPkt.numRetries++;
				uint32_t action = *(uint32_t*)(outBuf.data() + sizeof(PacketHeader));
				//					printf("Sending seq %d, retry %d action: %08x\n", m_NextSeq, numRetries, ntohl(action));
				sendto(m_Sock, (char*)outBuf.data(), (int)outBuf.size(), 0, (sockaddr*)&m_DestAddr, sizeof(m_DestAddr));
				outPkt.m_LastSendTime = now;
			}

		}
#ifdef _MSC_VER
		TIMEVAL timeout;
#else
		struct timeval timeout;
#endif
		timeout.tv_sec = 0;
		timeout.tv_usec = 200 * 1000;
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
				PacketHeader* hdr = (PacketHeader *)rcvBuf.data();

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

				if (hdr->isReply())
				{
//					printf("Got reply seq %d\n", hdr->seq);
					// Got reply, can discard the queue head
					if (!m_OutQueue.empty())
					{
						auto& pkt = m_OutQueue.front();
						PacketHeader* phdr = (PacketHeader*)pkt.packetPayload.data();
						if (phdr->seq == hdr->seq)
						{
							pkt.onResponse(rcvBuf, bytesReceived);
							m_OutQueue.pop_front();
						}
						else
						{
							LOG_F(ERROR, "Expected reply seq %d, got %d instead, disconnecting", phdr->seq, hdr->seq);
							Disconnect();
							return;
						}
						m_NextSeq++;
					}
				}
				else
				{
					if(m_StatusHandler)
						m_StatusHandler(rcvBuf, bytesReceived);
				}

			}

		}

	}

	private:
#ifdef _MSC_VER
	SOCKET m_Sock{ 0 };
#else
	int m_Sock{ 0 };
#endif


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

	std::chrono::time_point<std::chrono::system_clock> m_LastPacketRcvTime;
	std::chrono::time_point<std::chrono::system_clock> m_LastConfigReqTime;

};



class Runner
{
public:
	AlsavoSession m_Session;
	// List of status indices that are temperatures (should be divided by 10)
	std::set<int> m_TemperatureStatusIndices{ 16, 17, 18, 19, 20, 21, 23, 24, 55, 56 };
	std::chrono::time_point<std::chrono::system_clock> m_PrevKeepaliveSendTime;

	std::chrono::time_point<std::chrono::system_clock> m_SilenceOffSendTime;

	Runner()
		: m_Session	()
	{
		m_CurrConfigs.resize(64);
		m_CurrStatuses.resize(70);
	}

	bool m_OperationsDone = false;
	std::vector<int> m_CurrConfigs;
	std::vector<int> m_CurrStatuses;

	void HandleParamBlock(ParamBlock* block, bool isConfigs)
	{
		int startIdx = ntohs(block->startIdx);
		int numParams = ntohs(block->numParams);
		if (isConfigs && numParams + startIdx > m_CurrConfigs.size())
			m_CurrConfigs.resize(numParams + startIdx);
		if (!isConfigs && numParams + startIdx > m_CurrStatuses.size())
			m_CurrStatuses.resize(numParams + startIdx);

		if(s_JSONOutput)
		{
			// Header
			if(isConfigs)
				printf("\"config\": {\n");
			else
				printf("\"status\": {\n");
		}

		bool hasPrev = false;
		for (int i = startIdx; i < startIdx + numParams; ++i)
		{
			int16_t valInt = ntohs(block->payload[i - startIdx]);
			if (valInt == -21931)
				continue;
			if(isConfigs)
			{
				m_CurrConfigs[i] = valInt;
				if(s_JSONOutput)
				{
					if(hasPrev)
						printf(",\n");
					printf("\"%d\" : %d", i, valInt);
					hasPrev = true;
				}
				else
				{
					printf("/home/alsavo/config/%d={\"type\":\"config\", \"index\":%d, \"value\":%d}\n",i, i, valInt);
				}
			}
			else
			{
				m_CurrStatuses[i] = valInt;
				if(s_JSONOutput)
				{
					if(hasPrev)
						printf(",\n");
					printf("\"%d\" : ", i);
					if (m_TemperatureStatusIndices.find(i) != m_TemperatureStatusIndices.end())
					{
						float fval = ((float)valInt) / 10.0f;
						printf("%.1f", fval);
					}
					else
						printf("%d", valInt);
					
					hasPrev = true;


				}
				else
				{
					if (m_TemperatureStatusIndices.find(i) != m_TemperatureStatusIndices.end())
					{
						float fval = ((float)valInt) / 10.0f;
						printf("/home/alsavo/status/%d={\"type\":\"status\", \"index\":%d, \"value\":%.1f}\n", i, i, fval);
					}
					else
						printf("/home/alsavo/status/%d={\"type\":\"status\", \"index\":%d, \"value\":%d}\n", i, i, valInt);
				}
			}
		}
		if(s_JSONOutput)
		{
			printf("\n}");
			if(!isConfigs) // Status is printed out first
				printf(",");
			printf("\n");
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
			QueryObject* obj = (QueryObject*)&payload[4];
			for (int i = 0; i < objectCount; ++i)
			{
				ParseObject(obj);
				int16_t dataSize = ntohs(obj->dataSize);
				obj = (QueryObject*)(((char*)obj) + dataSize + 8);
			}

			if (cmd == 0x0b)
			{
				m_Session.SendPacketNow({ 0x0b, 0x01, 0, 0, 0, 2, 0, 0x2e, 0, payload[9], 0, 0 }, hdr->seq, true);
			}
		}
	}
	bool m_SilenceCommandSent = false;

	int main()
	{
		m_Session.SetStatusPacketHandler([this](const std::vector<unsigned char>& packet, int byteCount) {	DefaultHandler(packet, byteCount);	});

		for (int i = 0; i < 3; ++i)
		{
			m_Session.Connect(s_ServerAddr, s_ServerPort, s_SerialNumber, s_Password);
			if (m_Session.GetConnectionStatus() == AlsavoSession::ConnectionStatus::Connected)
				break;
		}
		if (m_Session.GetConnectionStatus() != AlsavoSession::ConnectionStatus::Connected)
			return -1;

		m_PrevKeepaliveSendTime = std::chrono::system_clock::now();

		if (s_ConfigIndex != -1 && s_ConfigValue != -1)
		{
			m_Session.SetConfig(s_ConfigIndex, s_ConfigValue, [this](const std::vector<unsigned char>& packet, int byteCount) {	DefaultHandler(packet, byteCount); });
		}
		if(s_JSONOutput)
			printf("{\n");
		m_Session.QueryAll([this](const std::vector<unsigned char>& packet, int byteCount)
			{
				DefaultHandler(packet, byteCount);
				if (s_Silence)
				{
					float currTemp = ((float)m_CurrStatuses[16]) / 10.0f;
					float tgtTemp = roundf(currTemp) + 1.0f;
					LOG_F(INFO, "Setting temperature and turning off heater (conf 4 to %d)", m_CurrConfigs[4] & 0xFFDF);
					m_Session.SetConfig(1, (int16_t)(tgtTemp * 10.0f), [this](const std::vector<unsigned char>& packet, int byteCount) {	DefaultHandler(packet, byteCount); });
					m_Session.SetConfig(4, m_CurrConfigs[4] & 0xFFDF, [this](const std::vector<unsigned char>& packet, int byteCount) {	DefaultHandler(packet, byteCount); });
					m_SilenceOffSendTime = std::chrono::system_clock::now();
					m_SilenceCommandSent = true;
				}				
				else if (!s_Listen)
					m_OperationsDone = true;
			});
		std::chrono::duration<float, std::milli> silenceTimeout{ 3000.0f };


		std::chrono::duration<float, std::milli> keepaliveTimeout{ 2000.0f };

		while(!m_OperationsDone && (m_Session.GetConnectionStatus() == AlsavoSession::ConnectionStatus::Connected))
		{
			m_Session.Pump();

			if (s_Silence && m_SilenceCommandSent)
			{
				if (std::chrono::system_clock::now() - m_SilenceOffSendTime > silenceTimeout)
				{
					LOG_F(INFO, "Restarting heater");
					m_SilenceCommandSent = false;
					m_Session.SetConfig(4, m_CurrConfigs[4] | 0x20, [this](const std::vector<unsigned char>& packet, int byteCount) {	DefaultHandler(packet, byteCount); });
					m_Session.QueryAll([this](const std::vector<unsigned char>& packet, int byteCount)
						{
							DefaultHandler(packet, byteCount);
							if (!s_Listen)
								m_OperationsDone = true;
						});
				}
			}

/* KEEPALIVE PACKETS, they don't seem to do anything

			if (std::chrono::system_clock::now() - m_PrevKeepaliveSendTime > keepaliveTimeout)
			{
				m_Session.SendPacket({ 1, 0, 0, 0 }, [](const std::vector<unsigned char>& packet, int byteCount) {}, 0xf3);
				m_PrevKeepaliveSendTime = std::chrono::system_clock::now();
			}*/
		}
		if(s_JSONOutput)
			printf("}\n");
		m_Session.Disconnect();

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
	app.add_flag("--listen", s_Listen, "Keep listening for status updates, not very reliable");
	app.add_flag("--silence", s_Silence, "Tap the brakes; set target temp to the current water out temp (rounded to nearest C) + 1, send power off + wait 2.5 seconds + power on");
	app.add_flag("--json", s_JSONOutput, "JSON output");
	app.add_option("-g,--logfile", logFile, "Write log to file");
	app.add_option("conf_idx", s_ConfigIndex, "Config index to write");
	app.add_option("value", s_ConfigValue, "Value to write");
	app.add_option("-v", s_verbosity, "Set verbosity level (0-3)");

	CLI11_PARSE(app, argc, argv);

	loguru::init(argc, argv);

	if (!logFile.empty())
		loguru::add_file(logFile.c_str(), loguru::Truncate, loguru::Verbosity_INFO);

	Runner r;
	return r.main();
}