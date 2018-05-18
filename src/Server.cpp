#include "Server.h"

#ifndef _WIN32
#include <signal.h>
#endif

namespace ws28{

Server::Server(int port, uv_loop_t *loop, bool ipv4Only, SSL_CTX *ctx) : m_pLoop(loop), m_pSSLContext(ctx){
#ifndef _WIN32
	signal(SIGPIPE, SIG_IGN);
#endif
	
	m_fnCheckConnection = [](HTTPRequest &req) -> bool {
		const char *host = nullptr;
		
		for(auto &p : req.headers.equal_range_ex("host")){
			if(host != nullptr) return false; // Multiple Host headers, better deny
			host = p.second;
		}
		
		if(host == nullptr) return true; // No host header, default to accept
		
		const char *origin = nullptr;
		
		for(auto &p : req.headers.equal_range_ex("origin")){
			if(origin != nullptr) return false; // Multiple Origin headers, better deny
			origin = p.second;
		}
		
		if(origin == nullptr) return true;
		
		return strcmp(origin, host) == 0;
	};
	
	m_Server.data = this;
	
	uv_tcp_init(uv_default_loop(), &m_Server);
	struct sockaddr_storage addr;
	
	if(ipv4Only){
		uv_ip4_addr("0.0.0.0", port, (struct sockaddr_in*) &addr);
	}else{
		uv_ip6_addr("::0", port, (struct sockaddr_in6*) &addr);
	}
	
	uv_tcp_nodelay(&m_Server, (int) true);
	
	if(uv_tcp_bind(&m_Server, (struct sockaddr*) &addr, 0) != 0){
		fprintf(stderr, "ws28: Couldn't bind\n");
		uv_close((uv_handle_t*) &m_Server, nullptr);
		abort();
	}
	
	if(uv_listen((uv_stream_t*) &m_Server, 256, [](uv_stream_t* server, int status){
		((Server*) server->data)->OnConnection(server, status);
	}) != 0){
		fprintf(stderr, "ws28: Couldn't start listening\n");
		uv_close((uv_handle_t*) &m_Server, nullptr);
		abort();
	}
}

Server::~Server(){
	while(!m_Clients.empty()){
		m_Clients.back()->Destroy(); // This will remove the client from the vector
	}
	
	uv_close((uv_handle_t*) &m_Server, nullptr);
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
			client->ClearServer();
			m_Clients.erase(it);
			break;
		}
	}
}

void Server::DetachClients(){
	for(auto &c : m_Clients){
		c->ClearServer();
	}
	
	m_Clients.clear();
}

}
