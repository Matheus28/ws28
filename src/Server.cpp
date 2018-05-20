#include "Server.h"

#ifndef _WIN32
#include <signal.h>
#endif

namespace ws28{

Server::Server(uv_loop_t *loop, SSL_CTX *ctx) : m_pLoop(loop), m_pSSLContext(ctx){

	m_fnCheckConnection = [](HTTPRequest &req) -> bool {
		const char *host = req.headers.m_hHost;
		if(host == nullptr) return true; // No host header, default to accept
		
		const char *origin = req.headers.m_hOrigin;
		if(origin == nullptr) return true;
		
		return strcmp(origin, host) == 0;
	};
	
	// m_Server.data = nullptr means we're not listening
	// m_Server.data = this means we are
	m_Server.data = nullptr;
}

bool Server::Listen(int port, bool ipv4Only){
	if(m_Server.data != nullptr) return false;
	
#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
	
	uv_tcp_init(m_pLoop, &m_Server);
	struct sockaddr_storage addr;
	
	if(ipv4Only){
		uv_ip4_addr("0.0.0.0", port, (struct sockaddr_in*) &addr);
	}else{
		uv_ip6_addr("::0", port, (struct sockaddr_in6*) &addr);
	}
	
	uv_tcp_nodelay(&m_Server, (int) true);
	
	if(uv_tcp_bind(&m_Server, (struct sockaddr*) &addr, 0) != 0){
		uv_close((uv_handle_t*) &m_Server, nullptr);
		return false;
	}
	
	if(uv_listen((uv_stream_t*) &m_Server, 512, [](uv_stream_t* server, int status){
		((Server*) server->data)->OnConnection(server, status);
	}) != 0){
		uv_close((uv_handle_t*) &m_Server, nullptr);
		return false;
	}
	
	m_Server.data = this;
	return true;
}

void Server::StopListening(){
	if(m_Server.data != this) return;
	uv_close((uv_handle_t*) &m_Server, nullptr);
	m_Server.data = nullptr;
}

Server::~Server(){
	StopListening();
	
	std::vector<Client*> clients;
	std::swap(clients, m_Clients);
	for(Client *c : clients){
		c->Destroy();
	}
}

void Server::OnConnection(uv_stream_t* server, int status){
	if(status < 0) return;
	
	uv_tcp_t *socket = new uv_tcp_t;
	socket->data = nullptr;

	uv_tcp_init(uv_default_loop(), socket);
	if(uv_accept(server, (uv_stream_t*) socket) == 0){
		m_Clients.push_back(new Client(this, socket));
	}else{
		uv_close((uv_handle_t*) socket, [](uv_handle_t *socket){
			delete (uv_tcp_t*) socket;
		});
	}
}

void Server::NotifyClientDestroyed(Client *client, bool handshakeCompleted){
	if(m_fnClientDisconnected && handshakeCompleted){
		m_fnClientDisconnected(client);
	}
	
	for(auto it = m_Clients.begin(); it != m_Clients.end(); ++it){
		if(*it == client){
			m_Clients.erase(it);
			break;
		}
	}
}

}
