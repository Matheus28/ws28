#ifndef H_2ABA91710E664A51814F459521E1C4D4
#define H_2ABA91710E664A51814F459521E1C4D4

#include <memory>
#include <string_view>
#include <map>

#include "Client.h"

namespace ws28 {
	
	class Server {
		typedef bool (*CheckConnectionFn)(Client *, std::string_view path, const std::multimap<std::string_view, std::string_view> &headers);
		typedef void (*ClientConnectedFn)(Client *);
		typedef void (*ClientDisconnectedFn)(Client *);
		typedef void (*ClientDataFn)(Client *, const char *, size_t);
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
		
		CheckConnectionFn m_fnCheckConnection;
		ClientConnectedFn m_fnClientConnected;
		ClientDisconnectedFn m_fnClientDisconnected;
		ClientDataFn m_fnClientData;
		
		friend class Client;
	};
	
}

#endif