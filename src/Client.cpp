#include "Client.h"
#include "Server.h"
#include "sha1.h"
#include "base64.h"
#include <string>
#include <sstream>
#include <cassert>

namespace ws28 {
	
namespace detail {
	bool equalsi(const char *a, const char *b){
		for(;;){
			if(tolower(*a) != tolower(*b)) return false;
			if(!*a) return true;
			
			++a;
			++b;
		}
	}
}

struct DataFrameHeader {
	char *data;
	
	DataFrameHeader(char *data) : data(data){
		
	}
	
	void reset(){
		data[0] = 0;
		data[1] = 0;
	}

	void fin(bool v) { data[0] &= ~(1 << 7); data[0] |= v << 7; }
	void rsv1(bool v) { data[0] &= ~(1 << 6); data[0] |= v << 6; }
	void rsv2(bool v) { data[0] &= ~(1 << 5); data[0] |= v << 5; }
	void rsv3(bool v) { data[0] &= ~(1 << 4); data[0] |= v << 4; }
	void mask(bool v) { data[1] &= ~(1 << 7); data[1] |= v << 7; }
	void opcode(uint8_t v) {
		data[0] &= ~0x0F;
		data[0] |= v & 0x0F;
	}

	void len(uint8_t v) {
		data[1] &= ~0x7F;
		data[1] |= v & 0x7F;
	}

	bool fin() { return (data[0] >> 7) & 1; }
	bool rsv1() { return (data[0] >> 6) & 1; }
	bool rsv2() { return (data[0] >> 5) & 1; }
	bool rsv3() { return (data[0] >> 4) & 1; }
	bool mask() { return (data[1] >> 7) & 1; }

	uint8_t opcode() {
		return data[0] & 0x0F;
	}

	uint8_t len() {
		return data[1] & 0x7F;
	}
};

Client::Client(Server *server, SocketHandle socket) : m_pServer(server), m_Socket(std::move(socket)){
	m_Socket->data = this;
	
	// Default to true since that's what most people want
	uv_tcp_nodelay(m_Socket.get(), true);
	
	uv_read_start((uv_stream_t*) m_Socket.get(), [](uv_handle_t*, size_t suggested_size, uv_buf_t *buf){
		buf->base = new char[suggested_size];
		buf->len = suggested_size;
	}, [](uv_stream_t* stream, ssize_t nread, const uv_buf_t* buf){
		auto client = (Client*) stream->data;
		
		// Both checks are needed because when we're destroying, only the second one is false
		if(client != nullptr && client->m_Socket){
			if(nread < 0){
				client->Destroy();
			}else if(nread > 0){
				client->OnRawSocketData(buf->base, (size_t) nread);
			}
		}
		
		if(buf != nullptr) delete[] buf->base;
	});
}

Client::~Client(){
	assert(!m_Socket);
}

void Client::Destroy(){
	if(!m_Socket) return;
	
	// Remove socket from our object, we'll put it in the shutdown request soon
	SocketHandle tmp = std::move(m_Socket);
	
	m_pServer->NotifyClientDestroyed(this, m_bHasCompletedHandshake);
	m_pServer = nullptr;
	
	struct ShutdownRequest : uv_shutdown_t {
		SocketHandle socket;
	};
	
	auto req = new ShutdownRequest;
	req->socket = std::move(tmp);
	
	uv_shutdown(req, (uv_stream_t*) req->socket.get(), [](uv_shutdown_t* reqq, int){
		auto req = (ShutdownRequest*) reqq;
		
		delete (Client*) req->socket->data;
		delete req;
	});
}


void Client::WriteDataFrameHeader(uint8_t opcode, size_t len, char *headerStart){
	DataFrameHeader header{ headerStart };
	
	header.reset();
	header.fin(true);
	header.opcode(opcode);
	header.mask(false);
	header.rsv1(false);
	header.rsv2(false);
	header.rsv3(false);
	if(len >= 126){
		if(len > UINT16_MAX){
			header.len(127);
			*(uint8_t*)(headerStart + 2) = (len >> 56) & 0xFF;
			*(uint8_t*)(headerStart + 3) = (len >> 48) & 0xFF;
			*(uint8_t*)(headerStart + 4) = (len >> 40) & 0xFF;
			*(uint8_t*)(headerStart + 5) = (len >> 32) & 0xFF;
			*(uint8_t*)(headerStart + 6) = (len >> 24) & 0xFF;
			*(uint8_t*)(headerStart + 7) = (len >> 16) & 0xFF;
			*(uint8_t*)(headerStart + 8) = (len >> 8) & 0xFF;
			*(uint8_t*)(headerStart + 9) = (len >> 0) & 0xFF;
		}else{
			header.len(126);
			*(uint8_t*)(headerStart + 2) = (len >> 8) & 0xFF;
			*(uint8_t*)(headerStart + 3) = (len >> 0) & 0xFF;
		}
	}else{
		header.len(len);
	}
}


size_t Client::GetDataFrameHeaderSize(size_t len){
	if(len >= 126){
		if(len > UINT16_MAX){
			return 10;
		}else{
			return 4;
		}
	}else{
		return 2;
	}
}

void Client::OnRawSocketData(char *data, size_t len){
	if(len == 0) return;
	if(!m_Socket) return;
	
	if(m_bWaitingForFirstPacket){
		m_bWaitingForFirstPacket = false;
		
		assert(!IsSecure());
		
		if(m_pServer->GetSSLContext() != nullptr && (data[0] == 0x16 || uint8_t(data[0]) == 0x80)){
			InitSecure();
		}
	}
	
	if(IsSecure()){
		if(!m_pTLS->ReceivedData(data, len, [&](char *data, size_t len){
			OnSocketData(data, len);
		})){
			return Destroy();
		}
		
		FlushTLS();
	}else{
		OnSocketData(data, len);
	}
}

void Client::OnSocketData(char *data, size_t len){
	// This gives us an extra byte just in case
	if(m_iBufferPos + len + 1 >= MAX_MESSAGE_SIZE){
		Destroy(); // Buffer overflow
		return;
	}
	
	// If we don't have anything stored in our class-level buffer (m_Buffer),
	// we use the buffer we received in the function arguments so we don't have to
	// perform any copying. The Bail function needs to be called before we leave this
	// function (unless we're destroying the client), to copy the unused part of the buffer
	// back to our class-level buffer
	char *buffer;
	size_t bufferLen;
	bool usingLocalBuffer;
	
	if(m_iBufferPos == 0){
		assert(!m_Buffer);
		usingLocalBuffer = true;
		buffer = data;
		bufferLen = len;
	}else{
		usingLocalBuffer = false;
		
		buffer = m_Buffer.get();
		
		memcpy(buffer + m_iBufferPos, data, len);
		m_iBufferPos += len;
		buffer[m_iBufferPos] = 0;
		bufferLen = m_iBufferPos;
	}
	
	
	
	auto Bail = [&](){
		// Copy partial HTTP headers to our buffer
		if(usingLocalBuffer && bufferLen > 0){
			assert(m_iBufferPos == 0);
			m_Buffer = std::make_unique<char[]>(MAX_MESSAGE_SIZE);
			memcpy(m_Buffer.get(), buffer, bufferLen);
			m_iBufferPos = bufferLen;
		}
	};
	
	if(!m_bHasCompletedHandshake){
		// HTTP headers not done yet, wait
		if(strstr((char*)buffer, "\r\n\r\n") == nullptr) return Bail();
		
		auto MalformedRequest = [&](){
			Write("HTTP/1.1 400 Bad Request\r\n\r\n");
			Destroy();
		};
		
		char *str = buffer;
		
		const char *method;
		const char *path;
		
		{
			auto methodEnd = strstr(str, " ");
			
			auto endOfLine = strstr(str, "\r\n");
			assert(endOfLine != nullptr); // Can't fail because of a check above
			
			if(methodEnd == nullptr || methodEnd > endOfLine) return MalformedRequest();
			
			method = str;
			*methodEnd = '\0';
			
			auto pathStart = methodEnd + 1;
			auto pathEnd = strstr(pathStart, " ");
			
			if(pathEnd == nullptr || pathEnd > endOfLine) return MalformedRequest();
			
			path = pathStart;
			*pathEnd = '\0';
			
			// Skip line
			str = endOfLine + 2;
		}
		
		RequestHeaders headers;
		
		for(;;) {
			auto nextLine = strstr(str, "\r\n");
			
			// This means that we have finished parsing the headers
			if(nextLine == str) {
				break;
			}
			
			if(nextLine == nullptr) return MalformedRequest();
			
			auto colonPos = strstr(str, ":");
			if(colonPos == nullptr || colonPos > nextLine) return MalformedRequest();
			
			auto keyStart = str;
			auto keyEnd = colonPos;
			
			// Key to lower case
			std::transform(keyStart, keyEnd, keyStart, ::tolower);
			
			
			auto valueStart = colonPos + 1;
			auto valueEnd = nextLine;
			
			
			// Trim spaces
			while(keyStart != keyEnd && *keyStart == ' ') ++keyStart;
			while(keyStart != keyEnd && *(keyEnd - 1) == ' ') --keyEnd;
			while(valueStart != valueEnd && *valueStart == ' ') ++valueStart;
			while(valueStart != valueEnd && *(valueEnd - 1) == ' ') --valueEnd;
			
			*keyEnd = '\0';
			*valueEnd = '\0';
			
			headers.Set(keyStart, valueStart);
			
			str = nextLine + 2;
		}
		
		HTTPRequest req{
			m_pServer,
			method,
			path,
			headers,
		};
		
		{
			if(headers.m_hUpgrade != nullptr){
				if(!detail::equalsi(headers.m_hUpgrade, "websocket")){
					return MalformedRequest();
				}
			}else{
				
				HTTPResponse res;
				
				if(m_pServer->m_fnHTTPRequest) m_pServer->m_fnHTTPRequest(req, res);
				
				if(res.statusCode == 0) res.statusCode = 404;
				if(res.statusCode < 200 || res.statusCode >= 1000) res.statusCode = 500;
				
				
				const char *statusCodeText = "WS28"; // Too lazy to create a table of those
				
				std::stringstream ss;
				ss << "HTTP/1.1 " << res.statusCode << " " << statusCodeText << "\r\n";
				ss << "Connection: close\r\n";
				ss << "Content-Length: " << res.body.size() << "\r\n";
				
				for(auto &p : res.headers){
					ss << p.first << ": " << p.second << "\r\n";
				}
				
				ss << "\r\n";
				
				ss << res.body;
				
				std::string str = ss.str();
				Write(str.data(), str.size());
				
				Destroy();
				return;
			}
		}
		
		if(headers.m_hConnection == nullptr) return MalformedRequest();
		if(!detail::equalsi(headers.m_hConnection, "upgrade")) return MalformedRequest();
		
		bool sendMyVersion = false;
		
		if(headers.m_hSecWebSocketVersion == nullptr) return MalformedRequest();
		if(!detail::equalsi(headers.m_hSecWebSocketVersion, "13")){
			sendMyVersion = true;
		}
		
		if(headers.m_hSecWebSocketKey == nullptr) return MalformedRequest();
		
		std::string securityKey = headers.m_hSecWebSocketKey;
		
		if(m_pServer->m_fnCheckConnection && !m_pServer->m_fnCheckConnection(req)){
			Write("HTTP/1.1 403 Forbidden\r\n\r\n");
			Destroy();
			return;
		}
		
		
		securityKey += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
		unsigned char hash[20];
		sha1::calc(securityKey.data(), securityKey.size(), hash);
		auto solvedHash = base64_encode(hash, sizeof(hash));
		
		char buf[256]; // We can use up to 101 + 27 + 28 + 1 characters, and we round up just because
		int bufLen = snprintf(buf, sizeof(buf),
			"HTTP/1.1 101 Switching Protocols\r\n"
			"Upgrade: websocket\r\n"
			"Connection: Upgrade\r\n"
			"%s"
			"Sec-WebSocket-Accept: %s\r\n\r\n",
			
			sendMyVersion ? "Sec-WebSocket-Version: 13\r\n" : "",
			solvedHash.c_str()
		);
		
		assert(bufLen >= 0 && (size_t) bufLen < sizeof(buf));
		
		Write(ToUniqueBuffer(buf, bufLen), bufLen);
		
		m_bHasCompletedHandshake = true;
		
		// Reset buffer, notice that this assumes that the browser won't send anything before
		// waiting for the header response to come. This line isn't actually needed but it's there for safety
		m_iBufferPos = 0;
		
		m_pServer->NotifyClientInit(this);
		
		return;
	}
	
	struct Corker {
		Client &client;
		
		Corker(Client &client) : client(client) { client.Cork(true); }
		~Corker(){ client.Cork(false); }
	};
	
	Corker corker{*this};
	
	for(;;){
		// Not enough to read the header
		if(bufferLen < 2) return Bail();
		
		DataFrameHeader header(buffer);
		
		if(header.rsv1() || header.rsv2() || header.rsv3()) return Destroy();

		char *curPosition = buffer + 2;

		size_t frameLength = header.len();
		if(frameLength == 126){
			if(bufferLen < 4) return Bail();
			frameLength = (*(uint8_t*)(curPosition) << 8) | (*(uint8_t*)(curPosition + 1));
			curPosition += 2;
		}else if(frameLength == 127){
			if(bufferLen < 10) return Bail();

			frameLength = ((uint64_t)*(uint8_t*)(curPosition) << 56) | ((uint64_t)*(uint8_t*)(curPosition + 1) << 48)
				| ((uint64_t)*(uint8_t*)(curPosition + 2) << 40) | ((uint64_t)*(uint8_t*)(curPosition + 3) << 32)
				| (*(uint8_t*)(curPosition + 4) << 24) | (*(uint8_t*)(curPosition + 5) << 16)
				| (*(uint8_t*)(curPosition + 6) << 8) | (*(uint8_t*)(curPosition + 7) << 0);

			curPosition += 8;
		}

		auto amountLeft = bufferLen - (curPosition - buffer);
		const char *maskKey = nullptr;
		if(header.mask()){
			if(amountLeft < 4) return Bail();
			maskKey = curPosition;
			curPosition += 4;
			amountLeft -= 4;
		}
		
		if(frameLength > amountLeft) return Bail();
		
		auto Unmask = [&](char *data, size_t len){
			if(header.mask()){
				for(size_t i = 0; i < (len & ~3); i += 4){
					data[i + 0] ^= maskKey[0];
					data[i + 1] ^= maskKey[1];
					data[i + 2] ^= maskKey[2];
					data[i + 3] ^= maskKey[3];
				}
				
				for(size_t i = len & ~3; i < len; ++i){
					data[i] ^= maskKey[i % 4];
				} 
			}
		};
		
		// Op codes can also never be fragmented
		if(header.opcode() >= 0x08){
			if(!header.fin()){
				return Destroy();
			}
			
			Unmask((char*) curPosition, frameLength);
			ProcessDataFrame(header.opcode(), curPosition, frameLength);
		}else if(m_Frames.empty() && header.fin()){
			// Fast path, we received a whole frame and we don't need to combine it with anything
			Unmask((char*) curPosition, frameLength);
			ProcessDataFrame(header.opcode(), curPosition, frameLength);
		}else{
			if(!m_Frames.empty()){
				if(header.opcode() != 0){
					return Destroy(); // Must be continuation frame op code
				}
			}
			
			{
				DataFrame frame{ header.opcode(), { curPosition, curPosition + frameLength } };
				Unmask(frame.data.data(), frame.data.size());
				m_Frames.emplace_back(std::move(frame));
			}
			
			size_t totalLength = 0;
			for(DataFrame &frame : m_Frames){
				totalLength += frame.data.size();
			}
			
			if(totalLength >= MAX_MESSAGE_SIZE) return Destroy();
				
			if(header.fin()){
				// Assemble frame
				
				auto allFrames = std::make_unique<char[]>(totalLength);
				
				size_t allFramesPos = 0;
				for(DataFrame &frame : m_Frames){
					memcpy(allFrames.get() + allFramesPos, frame.data.data(), frame.data.size());
					allFramesPos += frame.data.size();
				}

				ProcessDataFrame(m_Frames[0].opcode, allFrames.get(), totalLength);
				
				m_Frames.clear();
			}
			
		}
		
		// Consume buffer
		{
			size_t amount = (curPosition - buffer) + frameLength;
			
			if(usingLocalBuffer){
				buffer += amount;
				bufferLen -= amount;
			}else{
				memmove(m_Buffer.get(), m_Buffer.get() + amount, m_iBufferPos - amount);
				m_iBufferPos -= amount;
				// buffer = m_Buffer.get()
				bufferLen = m_iBufferPos;
				
				// Used up our class buffer, free it and make sure we crash if we try to use it further in this function
				if(bufferLen == 0){
					buffer = nullptr;
					m_Buffer.reset();
				}
			}
		}
	}
	
	// Unreachable
}


void Client::ProcessDataFrame(uint8_t opcode, const char *data, size_t len){
	if(opcode == 9){
		// Ping
		Send(data, len, 10); // Pong
	}else if(opcode == 8){
		// Close
		Destroy();
	}else if(opcode == 1 || opcode == 2){
		m_pServer->NotifyClientData(this, data, len);
	}
}

void Client::Send(const char *data, size_t len, uint8_t opCode){
	if(!m_Socket) return;
	
	auto fdata = std::make_unique<char[]>(len + GetDataFrameHeaderSize(len));
	
	WriteDataFrameHeader(opCode, len, fdata.get());
	memcpy(fdata.get() + GetDataFrameHeaderSize(len), data, len);
	Write(std::move(fdata), len + GetDataFrameHeaderSize(len));
}


void Client::InitSecure(){
	m_pTLS = std::make_unique<TLS>(m_pServer->GetSSLContext());
}


void Client::FlushTLS(){
	assert(m_pTLS != nullptr);
	m_pTLS->ForEachPendingWrite([&](const char *data, size_t len){
		WriteRaw(ToUniqueBuffer(data, len), len);
	});
}

void Client::Write(const char *data, size_t len){
	if(IsSecure()){
		if(!m_pTLS->Write(data, len)) return Destroy();
		FlushTLS();
	}else{
		WriteRaw(ToUniqueBuffer(data, len), len);
	}
}

void Client::Write(std::unique_ptr<char[]> data, size_t len){
	if(IsSecure()){
		if(!m_pTLS->Write(data.get(), len)) return Destroy();
		FlushTLS();
	}else{
		WriteRaw(std::move(data), len);
	}
}


std::unique_ptr<char[]> Client::ToUniqueBuffer(const char *buf, size_t len){
	auto d = std::make_unique<char[]>(len);
	memcpy(d.get(), buf, len);
	return d;
}


void Client::WriteRaw(std::unique_ptr<char[]> data, size_t len){
	if(!m_Socket) return;
	
	// Try to write without allocating memory first, if that doesn't work, we call WriteRawQueue
	uv_buf_t buf;
	buf.base = data.get();
	buf.len = len;
	
	int written = uv_try_write((uv_stream_t*) m_Socket.get(), &buf, 1);
	if(written != UV_EAGAIN){
		assert(written != 0);
		if(written > 0){
			if((size_t) written == len) return; // <= This should be the common case
			
			// Partial write
			
			// This is bad, but it should be rare
			// We need to reallocate the buffer so it gets freed properly
			// There are better ways to do this, but I'm lazy
			
			WriteRawQueue(ToUniqueBuffer(data.get() + written, len - written), len - written);
		}else{
			// Write error
			Destroy();
			return;
		}
	}else{
		WriteRawQueue(std::move(data), len);
	}
}

void Client::WriteRawQueue(std::unique_ptr<char[]> data, size_t len){
	struct CustomWriteRequest {
		uv_write_t req;
		uv_buf_t buf;
		Client *client;
		std::unique_ptr<char[]> data;
	};

	auto request = new CustomWriteRequest();
	request->buf.base = data.get();
	request->buf.len = len;
	request->client = this;
	request->data = std::move(data);
	
	if(uv_write(&request->req, (uv_stream_t*) m_Socket.get(), &request->buf, 1, [](uv_write_t* req, int status){
		auto request = (CustomWriteRequest*) req;

		if(status < 0){
			request->client->Destroy();
		}
		
		delete request;
	}) != 0){
		delete request;
		Destroy();
	}
}

void Client::Cork(bool v){
	if(!m_Socket) return;
	
	int enable = v;
	uv_os_fd_t fd;
	uv_fileno((uv_handle_t*) m_Socket.get(), &fd);
	
	// Shamelessly copied from uWebSockets
#if defined(TCP_CORK)
	// Linux
	setsockopt(fd, IPPROTO_TCP, TCP_CORK, &enable, sizeof(int));
#elif defined(TCP_NOPUSH)
	// Mac OS X & FreeBSD
	setsockopt(fd, IPPROTO_TCP, TCP_NOPUSH, &enable, sizeof(int));
	
	// MacOS needs this to flush the messages out
	if(!enable){
		::send(fd, "", 0, 0);
	}
#endif
}


}
