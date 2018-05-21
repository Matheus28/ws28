#ifndef H_0AC5AB22DD724A3F8FE93E27C178D633
#define H_0AC5AB22DD724A3F8FE93E27C178D633

#include <cstdint>
#include <memory>
#include <uv.h>
#include <algorithm>
#include <map>

#include "Headers.h"
#include "TLS.h"

namespace ws28 {
	namespace detail {
		struct Corker;
		struct SocketDeleter {
			void operator()(uv_tcp_t *socket) const {
				if(socket == nullptr) return;
				uv_close((uv_handle_t*) socket, [](uv_handle_t *h){
					delete (uv_tcp_t*) h;
				});
			}
		};
	}
	
	typedef std::unique_ptr<uv_tcp_t, detail::SocketDeleter> SocketHandle;
	
	class Server;
	class Client {
		enum { MAX_MESSAGE_SIZE = 16 * 1024 };
		enum { MAX_NUM_FRAMES = 1024 };
	public:
		~Client();
		
		void Destroy();
		void Send(const char *data, size_t len, uint8_t opCode = 2);
		
		inline void SetUserData(void *v){ m_pUserData = v; }
		inline void* GetUserData(){ return m_pUserData; }
		
		inline bool IsSecure(){ return m_pTLS != nullptr; }
		
		inline Server* GetServer(){ return m_pServer; }
		
	private:
		
		struct DataFrame {
			uint8_t opcode;
			std::vector<char> data;
		};
		
		Client(Server *server, SocketHandle socket);
		
		Client(const Client &other) = delete;
		Client& operator=(Client &other) = delete;
		
		size_t GetDataFrameHeaderSize(size_t len);
		void WriteDataFrameHeader(uint8_t opcode, size_t len, char *out);
		void EncryptAndWrite(const char *data, size_t len);
		
		void OnRawSocketData(char *data, size_t len);
		void OnSocketData(char *data, size_t len);
		void ProcessDataFrame(uint8_t opcode, const char *data, size_t len);
		
		void InitSecure();
		void FlushTLS();
		
		void Write(const char *data){ Write(data, strlen(data)); }
		void Write(const char *data, size_t len);
		void WriteRaw(const char *data, size_t len);
		void WriteRawQueue(std::unique_ptr<char[]> data, size_t len);
		
		void Cork(bool v);
		void ForceCork(bool v);
		
		void SendDataFrameHeader(size_t payloadLen, uint8_t opCode);
		
		std::unique_ptr<char[]> ToUniqueBuffer(const char *buf, size_t len);
		
		
		Server *m_pServer;
		SocketHandle m_Socket;
		void *m_pUserData = nullptr;
		bool m_bWaitingForFirstPacket = true;
		bool m_bHasCompletedHandshake = false;
		
		std::unique_ptr<TLS> m_pTLS;
		std::vector<DataFrame> m_Frames;
		
		size_t m_iCorkCounter = 0;
		
		size_t m_iBufferPos = 0;
		std::unique_ptr<char[]> m_Buffer;
		
		friend class Server;
		friend struct detail::Corker;
		friend class std::unique_ptr<Client>;
	};
	
}

#endif
