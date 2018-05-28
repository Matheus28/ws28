#ifndef H_2ABA91710E664A51814F459521E1C4D4
#define H_2ABA91710E664A51814F459521E1C4D4

#include <memory>
#include <map>
#include <string>
#include <cassert>

#include "Client.h"

namespace ws28 {
	class Server;
	
	struct HTTPRequest {
		Server *server;
		const char *method;
		const char *path;
		const char *ip;
		
		// Header keys are always lower case
		const RequestHeaders &headers;
	};
	
	class HTTPResponse {
	public:
		
		HTTPResponse& status(int v){ statusCode = v; return *this; }
		HTTPResponse& send(const char *v){ if(statusCode == 0) statusCode = 200; body.append(v); return *this; }
		HTTPResponse& send(const std::string &v){ return send(v.c_str()); }
		
		// Appends a response header. The following headers cannot be changed:
		// Connection: close
		// Content-Length: body.size()
		HTTPResponse& header(const std::string &key, const std::string &value){ headers.emplace(key, value); return *this; }
		
	private:
		int statusCode = 0;
		std::string body;
		std::multimap<std::string, std::string> headers;
		
		friend class Client;
	};
	
	class Server {
		typedef bool (*CheckConnectionFn)(HTTPRequest&);
		typedef void (*ClientConnectedFn)(Client *);
		typedef void (*ClientDisconnectedFn)(Client *);
		typedef void (*ClientDataFn)(Client *, const char *data, size_t len, int opcode);
		typedef void (*HTTPRequestFn)(HTTPRequest&, HTTPResponse&);
	public:
		
		// Note: By default, this listens on both ipv4 and ipv6
		// Note: if you provide a SSL_CTX, this server will listen to *BOTH* secure and insecure connections at that port,
		//       sniffing the first byte to figure out whether it's secure or not
		Server(uv_loop_t *loop, SSL_CTX *ctx = nullptr);
		Server(const Server &other) = delete;
		Server& operator=(const Server &other) = delete;
		~Server();
		
		bool Listen(int port, bool ipv4Only = false);
		void StopListening();
		void DestroyClients();
		
		// This callback is called when the client is trying to connect using websockets
		// By default, for safety, this checks the Origin and makes sure it matches the Host
		// It's likely you wanna change this check if your websocket server is in a different domain.
		void SetCheckConnectionCallback(CheckConnectionFn v){ m_fnCheckConnection = v; }
		
		// This callback is called when a client establishes a connection (after websocket handshake)
		// This is paired with the disconnected callback
		void SetClientConnectedCallback(ClientConnectedFn v){ m_fnClientConnected = v; }
		
		// This callback is called when a client disconnects
		// This is paired with the connected callback, and will *always* be called for clients that called the other callback
		// Note that clients grab this value when you call Destroy on them, so changing this after clients are connected
		// might lead to weird results. In practice, just set it once and forget about it.
		void SetClientDisconnectedCallback(ClientDisconnectedFn v){ m_fnClientDisconnected = v; }
		
		// This callback is called when the client receives a data frame
		// Note that both text and binary op codes end up here
		void SetClientDataCallback(ClientDataFn v){ m_fnClientData = v; }
		
		// This callback is called when a normal http request is received
		// If you don't send anything in response, the status code is 404
		// If you send anything in response without setting a specific status code, it will be 200
		// Connections that call this callback never lead to a connection
		void SetHTTPCallback(HTTPRequestFn v){ m_fnHTTPRequest = v;}
		
		SSL_CTX* GetSSLContext() const { return m_pSSLContext; }
		
		inline void SetUserData(void *v){ m_pUserData = v; }
		inline void* GetUserData() const { return m_pUserData; }
		
		// Adjusts how much we're willing to accept from clients
		// Note: this can only be set while we don't have clients (preferably before listening)
		inline void SetMaxMessageSize(size_t v){ assert(m_Clients.empty()); m_iMaxMessageSize = v;}
		
		void Ref(){ if(m_Server) uv_ref((uv_handle_t*) m_Server.get()); }
		void Unref(){ if(m_Server) uv_unref((uv_handle_t*) m_Server.get()); }
		
	private:
		void OnConnection(uv_stream_t* server, int status);
		
		void NotifyClientInit(Client *client){
			if(m_fnClientConnected) m_fnClientConnected(client);
		}
		
		std::unique_ptr<Client> NotifyClientPreDestroyed(Client *client);
		
		void NotifyClientData(Client *client, const char *data, size_t len, int opcode){
			if(m_fnClientData) m_fnClientData(client, data, len, opcode);
		}
		
		uv_loop_t *m_pLoop;
		SocketHandle m_Server;
		SSL_CTX *m_pSSLContext;
		void *m_pUserData = nullptr;
		std::vector<std::unique_ptr<Client>> m_Clients;
		
		CheckConnectionFn m_fnCheckConnection = nullptr;
		ClientConnectedFn m_fnClientConnected = nullptr;
		ClientDisconnectedFn m_fnClientDisconnected = nullptr;
		ClientDataFn m_fnClientData = nullptr;
		HTTPRequestFn m_fnHTTPRequest = nullptr;
		
		size_t m_iMaxMessageSize = 16 * 1024;
		
		friend class Client;
	};
	
}

#endif