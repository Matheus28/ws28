#ifndef H_2ABA91710E664A51814F459521E1C4D4
#define H_2ABA91710E664A51814F459521E1C4D4

#include <memory>
#include <map>
#include <string>

#include "Client.h"

namespace ws28 {
	class Server;
	
	struct HTTPRequest {
		const char *method;
		const char *path;
		
		// Header keys are always lower case
		const detail::multihash &headers;
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
		typedef void (*ClientDataFn)(Client *, const char *, size_t);
		typedef void (*HTTPRequestFn)(HTTPRequest&, HTTPResponse&);
	public:
		
		// Note: if you provide a SSL_CTX, this server will listen to *BOTH* secure and insecure connections at that port,
		//       sniffing the first byte to figure out whether it's secure or not
		Server(int port, uv_loop_t *loop, SSL_CTX *ctx = nullptr);
		Server(const Server &other) = delete;
		~Server();
		
		// Dettaches clients from this server
		// You can call this before destroying this server to keep clients around after it's destroyed
		// (default behavior is to destroy all clients when the server is destroyed)
		void DettachClients(){ m_Clients.clear(); }
		
		// This callback is called when the client is trying to connect using websockets
		// By default, for safety, this checks the Origin and makes sure it matches the Host
		// It's likely you wanna change this check if your websocket server is in a different domain.
		void SetCheckConnectionCallback(CheckConnectionFn v){ m_fnCheckConnection = v; }
		
		// This callback is called when a client establishes a connection (after websocket handshake)
		// This is paired with the disconnected callback
		void SetClientConnectedCallback(ClientConnectedFn v){ m_fnClientConnected = v; }
		
		// This callback is called when a client disconnects
		// This is paired with the connected callback
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
		
	private:
		void OnConnection(uv_stream_t* server, int status);
		
		void NotifyClientInit(Client *client){
			if(m_fnClientConnected) m_fnClientConnected(client);
		}
		
		void NotifyClientDestroyed(Client *client, bool handshakeCompleted);
		
		void NotifyClientData(Client *client, const char *data, size_t len){
			if(m_fnClientData) m_fnClientData(client, data, len);
		}
		
		uv_loop_t *m_pLoop;
		uv_tcp_t m_Server;
		SSL_CTX *m_pSSLContext;
		std::vector<Client*> m_Clients;
		
		CheckConnectionFn m_fnCheckConnection = nullptr;
		ClientConnectedFn m_fnClientConnected = nullptr;
		ClientDisconnectedFn m_fnClientDisconnected = nullptr;
		ClientDataFn m_fnClientData = nullptr;
		HTTPRequestFn m_fnHTTPRequest = nullptr;
		
		friend class Client;
	};
	
}

#endif