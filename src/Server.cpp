#include "Server.h"

namespace ws28{

Server::Server(int port, uv_loop_t *loop, SSL_CTX *ctx) : m_pLoop(loop), m_pSSLContext(ctx){
	m_fnCheckConnection = [](Client *, std::string_view path, const std::multimap<std::string_view, std::string_view> &headers) -> bool {
		std::string_view host;
		
		for(auto &[key, value] : detail::pair_range(headers.equal_range("host"))){
			if(host.data() != nullptr) return false; // Multiple Host headers, better deny
			host = value;
		}
		
		if(host.data() == nullptr) return true; // No host header, default to accept
		
		std::string_view origin;
		
		for(auto &[key, value] : detail::pair_range(headers.equal_range("origin"))){
			if(origin.data() != nullptr) return false; // Multiple Origin headers, better deny
			origin = value;
		}
		
		if(origin.data() == nullptr) return true;
		
		return origin == host;
	};
	
	m_Server.data = this;
	
	uv_tcp_init(uv_default_loop(), &m_Server);
	struct sockaddr_in addr;
	uv_ip4_addr("0.0.0.0", port, &addr);
	uv_tcp_nodelay(&m_Server, (int) true);
	
	if(uv_tcp_bind(&m_Server, (const struct sockaddr*) &addr, 0) != 0){
		puts("ws28: Couldn't bind");
		uv_close((uv_handle_t*) &m_Server, nullptr);
		abort();
	}
	
	if(uv_listen((uv_stream_t*) &m_Server, 256, [](uv_stream_t* server, int status){
		((Server*) server->data)->OnConnection(server, status);
	}) != 0){
		puts("ws28: Couldn't start listening");
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
			m_Clients.erase(it);
			break;
		}
	}
}

}
