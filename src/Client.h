#ifndef H_0AC5AB22DD724A3F8FE93E27C178D633
#define H_0AC5AB22DD724A3F8FE93E27C178D633

#include <cstdint>
#include <memory>
#include <uv.h>
#include <algorithm>
#include <map>

#include "TLS.h"

namespace ws28 {
	
	namespace detail {
		template<typename T>
		struct pair_range {
			pair_range(const std::pair<T, T> &p) : p(p){}
			
			T begin(){ return p.first; }
			T end(){ return p.second; }
			
			const std::pair<T, T> &p;
		};
		
		bool equalsi(const char *a, const char *b);
		
		struct multimap_compare {
			inline bool operator()(const char *a, const char *b) const {
				return std::lexicographical_compare(a, a + strlen(a), b, b + strlen(b));
			}
		};
		
		class multihash : public std::multimap<const char*, const char*, multimap_compare> {
		public:
			pair_range<iterator> equal_range_ex(const char *key){
				return pair_range<iterator>(equal_range(key));
			}
			
			pair_range<const_iterator> equal_range_ex(const char *key) const{
				return pair_range<const_iterator>(equal_range(key));
			}
		};
	}
	
	class Server;
	class Client {
		enum { MAX_MESSAGE_SIZE = 16 * 1024 };
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
		
		Client(Server *server, uv_tcp_t *h);
		
		Client(const Client &other) = delete;
		Client& operator=(Client &other) = delete;
		
		size_t GetDataFrameHeaderSize(size_t len);
		void WriteDataFrameHeader(uint8_t opcode, size_t len, char *out);
		void EncryptAndWrite(const char *data, size_t len);
		void WriteRaw(const char *data, size_t len);
		
		void OnRawSocketData(const char *data, size_t len);
		void OnSocketData(const char *data, size_t len);
		void ProcessDataFrame(uint8_t opcode, const char *data, size_t len);
		
		void InitSecure();
		void FlushTLS();
		
		void Write(const char *data){ Write(data, strlen(data)); }
		void Write(const char *data, size_t len);
		void Write(std::unique_ptr<char[]> data, size_t len);
		void WriteRaw(std::unique_ptr<char[]> data, size_t len);
		
		void Consume(size_t amount);
		
		std::unique_ptr<char[]> ToUniqueBuffer(const char *buf, size_t len);
		
		
		Server *m_pServer;
		uv_tcp_t *m_pSocket;
		void *m_pUserData = nullptr;
		bool m_bWaitingForFirstPacket = true;
		bool m_bHasCompletedHandshake = false;
		
		std::unique_ptr<TLS> m_pTLS;
		std::vector<DataFrame> m_Frames;
		
		size_t m_iBufferPos = 0;
		char m_Buffer[MAX_MESSAGE_SIZE];
		
		friend class Server;
		
	};
	
}

#endif
