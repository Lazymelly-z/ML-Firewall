#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <windivert.h>
#include <zmq.h>
#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <chrono>

#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "WinDivert.lib")
#pragma comment(lib, "C:\\Users\\OMEN\\Downloads\\vcpkg-master\\vcpkg-master\\installed\\x64-windows\\lib\\libzmq-mt-4_3_5.lib")
using namespace std;

// Variables 
// Global
UINT8 Packet [65535];
UINT PacketLen = 0;
PWINDIVERT_IPHDR IpHeader = NULL;
PWINDIVERT_IPV6HDR IpHeaderSix = NULL;
PWINDIVERT_TCPHDR TcpHeader = NULL;
PWINDIVERT_UDPHDR UdpHeader = NULL;
PVOID Payload = NULL;
UINT PayloadLen = 0;
WINDIVERT_ADDRESS Addr;
void* ZmqContext = nullptr;
void* ZmqSocket = nullptr;

struct IpAddr {
	bool IpV6;
	union {
		UINT32 V4;
		IN6_ADDR V6;
	}Addr;

	bool operator==(const IpAddr& other) const {
		if (IpV6 != other.IpV6) return false;
		if (IpV6)
			return memcmp(&Addr.V6, &other.Addr.V6, sizeof(IN6_ADDR)) == 0;
		else
			return Addr.V4 == other.Addr.V4;
	}
};


// Statefull Inspection
static size_t HashBytes(const void* data, size_t len, size_t seed = 0) {
	const auto* bytes = reinterpret_cast<const unsigned char*>(data);
	for (size_t i = 0; i < len; i++) {
		seed ^= bytes[i] + 0x9e3779b9 + (seed << 6) + (seed >> 2);
	}
	return seed;
}

static size_t HashIp(const IpAddr& ip) {
	size_t h = std::hash<bool>{}(ip.IpV6);
	if (ip.IpV6)
		h = HashBytes(&ip.Addr.V6, sizeof(IN6_ADDR), h);
	else
		h = HashBytes(&ip.Addr.V4, sizeof(UINT32), h);
	return h;
}

struct IpAddrHash {
	size_t operator()(const IpAddr& ip) const {return HashIp(ip);}
};

struct IpAddrEqual {
	bool operator()(const IpAddr& a, const IpAddr& b) const {return a == b;}
};

struct ConnectionKey {
	IpAddr SrcIp;
	IpAddr DstIp;
	UINT16 SrcPort;
	UINT16 DstPort;
	UINT8 Protocol;

	bool operator==(const ConnectionKey& other) const {
		return SrcIp == other.SrcIp &&
			   DstIp == other.DstIp &&
			   SrcPort == other.SrcPort &&
			   DstPort == other.DstPort &&
			   Protocol == other.Protocol;
	}
};

struct ConnectionKeyHash {
	size_t operator()(const ConnectionKey& k) const { // k = key
		size_t h = HashIp(k.SrcIp);
		h ^= HashIp(k.DstIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
		h ^= k.SrcPort + 0x9e3779b9 + (h << 6) + (h >> 2);
		h ^= k.DstPort + 0x9e3779b9 + (h << 6) + (h >> 2);
		h ^= k.Protocol + 0x9e3779b9 + (h << 6) + (h >> 2);
		
		return h;

	}
};

enum class ConnectionState {
	SYN_RECEIVED,
	ACTIVE,
	CLOSE
};

struct ConnectionTime {
	ConnectionState State;
	chrono::steady_clock::time_point LastSeen;
};

unordered_map<ConnectionKey, ConnectionTime, ConnectionKeyHash> ConnectionTable;

unordered_map<IpAddr, int, IpAddrHash, IpAddrEqual> HalfOpenCount; // Tracks half-open connections per IP
constexpr int MAX_HALF_OPEN = 15;

UINT32 MakeSynCookie(const IpAddr& SrcIp, const IpAddr& DstIp,
	UINT16 SrcPort, UINT16 DstPort) {
	const UINT32 Secret = 0xDEADBEEF;
	size_t h = HashIp(SrcIp);
	h ^= HashIp(DstIp) + 0x9e3779b9 + (h << 6) + (h >> 2);
	h = HashBytes(&SrcPort, sizeof(SrcPort), h);
	h = HashBytes(&DstPort, sizeof(DstPort), h);
	h ^= Secret;
	return (UINT32)(h & 0xFFFFFFFF);
}

bool ValidateSynCookie(UINT32 Cookie, const IpAddr& SrcIp, const IpAddr& DstIp,
	UINT16 SrcPort, UINT16 DstPort) {
	return Cookie == MakeSynCookie(SrcIp, DstIp, SrcPort, DstPort);
}

// ---------------------------------- //


enum class Zone {
	LOCAL, LOOPBACK, PUBLIC, BLOCKED
};

vector <IpAddr> BlackListedIPs = {
	// IpV4
	// [] {IpAddr a; a.IpV6 = false; a.Addr.V4 = inet_addr("1.2.3.4"); return a;}(),

	// IpV6
	// [] {IpAddr a; a.IpV6 = true; inet_pton(AF_INET6, "2001:db8::1", &a.Addr.V6); return a;}()
};

bool IsBlacklisted(const IpAddr& ip) {
	for (const auto& entry : BlackListedIPs) {
		if (ip == entry) return true;
	}
	return false;
}

// Firewall rules
// ------------------------------------- //

Zone GetZone(IpAddr Ip) {

	if (Ip.IpV6) {
		// ::1 is loopback
		const IN6_ADDR loopback = IN6ADDR_LOOPBACK_INIT;
		if (memcmp(&Ip.Addr.V6, &loopback, sizeof(IN6_ADDR)) == 0)
			return Zone::LOOPBACK;

		// fe80::/10 is link-local 
		if ((Ip.Addr.V6.u.Byte[0] == 0xFE) && (Ip.Addr.V6.u.Byte[1] & 0xC0) == 0x80)
			return Zone::LOCAL;

		if ((Ip.Addr.V6.u.Byte[0] & 0xFE) == 0xFC)
			return Zone::LOCAL;

		return Zone::PUBLIC;
	}

	const auto* Bytes = reinterpret_cast<const UINT8*>(&Ip.Addr.V4);
	UINT8 First = Bytes[0];
	UINT8 Second = Bytes[1];

	if (First == 127) {
		return Zone::LOOPBACK;
	}
	else if (First == 192 && Second == 168) {	
		return Zone::LOCAL;
	}
	else if (First == 10 || (First == 172 && (Second >= 16 && Second <= 31))) {
		return Zone::LOCAL;
	}
	else if (First == 169 && Second == 254) {
		return Zone::LOCAL;
	}
	else {
		return Zone::PUBLIC;
	}

}

string ZoneStr(Zone z) {
	switch (z) {
	case Zone::LOCAL: return "LOCAL";
	case Zone::LOOPBACK: return "LOOPBACK";
	case Zone::PUBLIC: return "PUBLIC";
	case Zone::BLOCKED: return "BLOCKED";
	default: return "Unknown";
	}
}


enum class Action {
	PASS, DROP
};

struct Rule {
	Zone SrcZone;
	Zone DstZone;
	UINT16 DstPort;
	UINT8 Protocol;
	Action Action;
	string Description;
};

vector <Rule> Rules = {
	{Zone::LOOPBACK, Zone::LOOPBACK, 0, 0, Action::PASS, "Allow Loopbacks"},
	{Zone::BLOCKED, Zone::LOCAL, 0, 0, Action::DROP, "Block Blacklisted IP"},
	{Zone::LOCAL, Zone::BLOCKED, 0, 0, Action::DROP, "Block to Blacklisted IP"},
	{Zone::PUBLIC, Zone::BLOCKED, 0, 0, Action::DROP, "Block to Blacklisted IP"},
	{Zone::LOCAL, Zone::PUBLIC, 0, 0, Action::PASS, "Allow sending everything out"},
	{Zone::PUBLIC, Zone::LOCAL, 80, 6, Action::DROP, "Block HTTP"},
	{Zone::PUBLIC, Zone::LOCAL, 22, 6, Action::DROP, "Block SSH"},
	{Zone::PUBLIC, Zone::LOCAL, 3389, 6, Action::DROP, "Block RDP"},
	{Zone::PUBLIC, Zone::LOCAL, 80, 6, Action::DROP, "Block HTTP"},
	{Zone::LOCAL, Zone::LOCAL, 0, 0, Action::PASS, "Allow sending to local network"}
};

Action RuleChecker(Zone SrcZone, Zone DstZone, UINT16 DstPort, UINT8 Protocol) {
	for (const Rule& r : Rules) {
		bool SrcMatch = (r.SrcZone == SrcZone);
		bool DstMatch = (r.DstZone == DstZone);
		bool PortMatch = (r.DstPort == 0 || r.DstPort == DstPort);
		bool ProtocolMatch = (r.Protocol == 0 || r.Protocol == Protocol);

		if (SrcMatch && DstMatch && PortMatch && ProtocolMatch) {
			return r.Action;
		}
	}

	return Action::PASS; // Default action 
	cout << "[ZONE] Src=" << ZoneStr(SrcZone) << " Dst=" << ZoneStr(DstZone) << endl; //Temp

}

void TrackConnection(IpAddr SrcIp, IpAddr DstIp, UINT16 SrcPort, UINT16 DstPort, UINT8 Protocol) {
	ConnectionKey key = { SrcIp, DstIp, SrcPort, DstPort,Protocol };
	ConnectionTable[key] = { ConnectionState::ACTIVE, chrono::steady_clock::now() };

	ConnectionKey reverse = { DstIp, SrcIp, DstPort, SrcPort, Protocol };
	ConnectionTable[reverse] = { ConnectionState::ACTIVE, chrono::steady_clock::now() };

	cout << "[TRACK] Tracking new connection SrcPort=" << SrcPort << " DstPort=" << DstPort << endl; //Temp
}

bool EstablishedConnection(IpAddr SrcIp, IpAddr DstIp, UINT16 SrcPort, UINT16 DstPort, UINT8 Protocol) {
	ConnectionKey key = { SrcIp, DstIp, SrcPort, DstPort,Protocol };
	auto It = ConnectionTable.find(key);

	if (It != ConnectionTable.end() && It->second.State == ConnectionState::ACTIVE) {
		It->second.LastSeen = chrono::steady_clock::now();
		cout << "[CONN] Existing connection found" << endl; // Temp
		return true;
	}
	cout << "[CONN] New connection" << endl; // Temp
	return false;
}

void OldConnection() {
	cout << "[TABLE] ConnectionTable size=" << ConnectionTable.size()
		<< " HalfOpen entries=" << HalfOpenCount.size() << endl; // Temp
	auto Now = chrono::steady_clock::now();
	for (auto It = ConnectionTable.begin(); It != ConnectionTable.end();) {
		auto age = chrono::duration_cast <chrono::seconds>(Now - It->second.LastSeen).count();
		int Timeout = (It->second.State == ConnectionState::SYN_RECEIVED) ? 5 : 120;
		if (age > Timeout) {
			It = ConnectionTable.erase(It);
		}
		else {
			++It;
		}
	}

		for (auto It = HalfOpenCount.begin(); It != HalfOpenCount.end();)
			It = (It->second <= 0) ? HalfOpenCount.erase(It) : ++It;

	}



void CloseConnection(IpAddr SrcIp, IpAddr DstIp, UINT16 SrcPort, UINT16 DstPort, UINT8 Protocol) {

	ConnectionKey key = {SrcIp, DstIp, SrcPort, DstPort,Protocol};
	ConnectionKey reverse = {DstIp, SrcIp, DstPort, SrcPort, Protocol};
	ConnectionTable.erase(key);
	ConnectionTable.erase(reverse);
}

// Ai
// ------------------------------------- //

Action QueryAI(
	UINT16 SrcPort, UINT16 DstPort,
	UINT8 Protocol, UINT PacketLen, UINT8 Flags) {

	
	char Msg[512];
	snprintf(Msg, sizeof(Msg),
		R"({"SrcPort":%d,"DstPort":%d,"Protocol":%d,"PacketLen":%d,"Flags":%d})",
		SrcPort, DstPort, Protocol,PacketLen, Flags
	);

	cout << "[AI] Sending: " << Msg << endl;
	int SendRc = zmq_send(ZmqSocket, Msg, strlen(Msg), 0);
	if (SendRc == -1) {
		cout << "[AI] Send failed — is Python running? Error=" << zmq_errno() << endl; // Error Debug

		zmq_close(ZmqSocket);
		ZmqSocket = zmq_socket(ZmqContext, ZMQ_REQ);
		int Timeout = 200;
		zmq_setsockopt(ZmqSocket, ZMQ_RCVTIMEO, &Timeout, sizeof(Timeout));
		zmq_connect(ZmqSocket, "tcp://127.0.0.1:5555"); // Resets the connection to the Python AI if it was lost

		return Action::PASS; 
	}

	char Reply[16] = {}; 
	int ReplyRc = zmq_recv(ZmqSocket, Reply, sizeof(Reply) - 1, 0);

	if (ReplyRc == -1) {
			ReplyRc = zmq_recv(ZmqSocket, Reply, sizeof(Reply) - 1, 0);
		if (ReplyRc == -1) {
			cout << "[AI] Reply failed — is Python running? Error=" << zmq_errno() << endl; // Error Debug

			zmq_close(ZmqSocket);
			ZmqSocket = zmq_socket(ZmqContext, ZMQ_REQ);
			int Timeout = 200;
			zmq_setsockopt(ZmqSocket, ZMQ_RCVTIMEO, &Timeout, sizeof(Timeout));
			zmq_connect(ZmqSocket, "tcp://127.0.0.1:5555"); // Resets the connection to the Python AI if it was lost
			return Action::PASS;
		}
	}
	cout << "[AI] Reply: " << Reply << endl; // Temp
	return (strncmp(Reply, "PASS", 4) == 0) ? Action::PASS : Action::DROP;
}


// -------------------------------------- //
void HandlePacket(HANDLE WdHandle, UINT8* Packet, UINT PacketLen, WINDIVERT_ADDRESS Addr) {

	// Reset variables
	PWINDIVERT_IPHDR IpHeader = NULL;
	PWINDIVERT_IPV6HDR IpHeaderSix = NULL;
	PWINDIVERT_TCPHDR TcpHeader = NULL;
	PWINDIVERT_UDPHDR UdpHeader = NULL;
	PVOID Payload = NULL;
	UINT PayloadLen = 0;

	WinDivertHelperParsePacket(Packet, PacketLen, &IpHeader, &IpHeaderSix, NULL, NULL, NULL, &TcpHeader, &UdpHeader, &Payload, &PayloadLen, NULL, NULL);


	IpAddr SrcIp = {0};
	IpAddr DstIp = {0};
	UINT16 SrcPort = 0;
	UINT16 DstPort = 0;
	UINT8 Protocol = 0;
	UINT8 Flags = 0;

	cout << "[PKT] Received packet len=" << PacketLen << endl; //Temp

	// Ip
	//---------------------------------------------- //
	if (IpHeader) { // If it's IPv4 
		SrcIp.IpV6 = false;
		SrcIp.Addr.V4 = IpHeader->SrcAddr;

		DstIp.IpV6 = false;
		DstIp.Addr.V4 = IpHeader->DstAddr;


	}

	else if (IpHeaderSix) { // If it's IPv6 
		SrcIp.IpV6 = true;
		memcpy(&SrcIp.Addr.V6, &IpHeaderSix->SrcAddr, sizeof(IN6_ADDR));

		DstIp.IpV6 = true;
		memcpy(&DstIp.Addr.V6, &IpHeaderSix->DstAddr, sizeof(IN6_ADDR));
	}
	else {
		return; // Not IP packet
	}

	// Protocol
	// --------------------------------------------- //

	if (IpHeader) { // If it's IPv4 
		Protocol = IpHeader->Protocol;
	}
	else if (IpHeaderSix) { // If it's IPv6 
		Protocol = IpHeaderSix->NextHdr;
	}

	if (TcpHeader) {
		SrcPort = ntohs(TcpHeader->SrcPort);
		DstPort = ntohs(TcpHeader->DstPort);
		//Int that represents the flags in a single byte for easier processing and sending to AI
		if (TcpHeader->Fin) Flags |= 1;
		if (TcpHeader->Syn) Flags |= 2;
		if (TcpHeader->Rst) Flags |= 4;
		if (TcpHeader->Psh) Flags |= 8;
		if (TcpHeader->Ack) Flags |= 16;
		if (TcpHeader->Urg) Flags |= 32;
	}

	else if (UdpHeader) {
		SrcPort = ntohs(UdpHeader->SrcPort);
		DstPort = ntohs(UdpHeader->DstPort);
	}

	if (TcpHeader) {
		bool IsSyn = TcpHeader->Syn && !TcpHeader->Ack;
		bool IsAck = !TcpHeader->Syn && TcpHeader->Ack;

		if (IsSyn) { //Syn Attack detection and mitigation using SYN cookies and half-open connection tracking
		if (HalfOpenCount[SrcIp] >= MAX_HALF_OPEN) {
			if (!IsBlacklisted(SrcIp))
				BlackListedIPs.push_back(SrcIp); // Add to blacklist 
			return; 
		}

		ConnectionKey key = { SrcIp, DstIp, SrcPort, DstPort, Protocol };
		ConnectionTable[key] = { ConnectionState::SYN_RECEIVED, chrono::steady_clock::now() };
		HalfOpenCount[SrcIp]++;

		WinDivertSend(WdHandle, Packet, PacketLen, NULL, &Addr);
		cout << "SYN received HalfOpen=" << HalfOpenCount[SrcIp] << endl;
		return;
	}

		if (IsAck) { // Validate SYN cookie and establish connection
		ConnectionKey synKey = { DstIp, SrcIp, DstPort, SrcPort, Protocol 
		
		};
		auto It = ConnectionTable.find(synKey);

		if (It != ConnectionTable.end() && It->second.State == ConnectionState::SYN_RECEIVED) {
			UINT32 Cookie = MakeSynCookie(SrcIp, DstIp, SrcPort, DstPort);
			UINT32 AckNum = ntohl(TcpHeader->AckNum);

			if (AckNum == Cookie + 1) {
				It->second.State = ConnectionState::ACTIVE;
				It->second.LastSeen = chrono::steady_clock::now();
				HalfOpenCount[SrcIp] = max(0, HalfOpenCount[SrcIp] - 1);
			}
			else {
				return; 
			}
		}
	}
	}


	if (EstablishedConnection(SrcIp, DstIp, SrcPort, DstPort, Protocol)) {

		if (TcpHeader && (TcpHeader->Fin || TcpHeader->Rst)) {
			CloseConnection(SrcIp, DstIp, SrcPort, DstPort, Protocol);
		}

		WinDivertSend(WdHandle, Packet, PacketLen, NULL, &Addr);
		return;
	}

	Zone SrcZone = GetZone(SrcIp);
	Zone DstZone = GetZone(DstIp);

	if (IsBlacklisted(SrcIp)) SrcZone = Zone::BLOCKED;
	if (IsBlacklisted(DstIp)) DstZone = Zone::BLOCKED;

	Action Decision = RuleChecker(SrcZone, DstZone, DstPort, Protocol);

	if (Decision == Action::PASS) { // Gives the packet info to the AI
		bool IsSyn = TcpHeader && TcpHeader->Syn && !TcpHeader->Ack;
		Decision = QueryAI(SrcPort, DstPort, Protocol, PacketLen, Flags);
	}

	if (Decision == Action::PASS) {
		TrackConnection(SrcIp, DstIp, SrcPort, DstPort, Protocol);
		WinDivertSend(WdHandle, Packet, PacketLen, NULL, &Addr);
	}

	cout << "[RULE] Decision=" << (Decision == Action::PASS ? "PASS" : "DROP") << endl; // Temp

	static int PacketCount = 0;
	if (++PacketCount % 50 == 0) {
		OldConnection();
	}
}

int main() {

	ZmqContext = zmq_ctx_new();
	ZmqSocket = zmq_socket(ZmqContext, ZMQ_REQ);

	int Timeout = 500; //ms
	zmq_setsockopt(ZmqSocket, ZMQ_RCVTIMEO, &Timeout, sizeof(Timeout));

	zmq_connect(ZmqSocket, "tcp://127.0.0.1:5555");
	Sleep (500); // Wait for the Python AI to start and bind the socket

	HANDLE Handle = WinDivertOpen("true", WINDIVERT_LAYER_NETWORK, 0, 0);

	if (Handle == INVALID_HANDLE_VALUE) {
		cerr << "Failed to open WinDivert handle: " << GetLastError() << endl; // Prints the error code if the handle fails to open
	}

	while (true) {
		if (!WinDivertRecv(Handle, Packet, sizeof(Packet), &PacketLen, &Addr)) break;

		HandlePacket(Handle, Packet, PacketLen, Addr);
	}

	zmq_close(ZmqSocket);
	zmq_ctx_destroy(ZmqContext);

	WinDivertClose(Handle);
	return 0;
}
