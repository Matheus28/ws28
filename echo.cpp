#include "src/Server.h"
#include <sstream>


int main(){
	static volatile sig_atomic_t quit = false;
	
	signal(SIGINT, [](int){
		if(quit){
			exit(1);
		}else{
			quit = true;
		}
	});
	
	ws28::Server s{uv_default_loop()};
	
	static intptr_t userID = 0;
	
	s.SetClientConnectedCallback([](ws28::Client *client){
		client->SetUserData((void*) ++userID);
		//printf("Client %d connected\n", (int) userID);
	});
	
	s.SetClientDisconnectedCallback([](ws28::Client *client){
		//printf("Client %d disconnected\n", (int) (intptr_t) client->GetUserData());
	});
	
	s.SetClientDataCallback([](ws28::Client *client, const char *data, size_t len){
		//printf("Client %d: %.*s\n", (int) (intptr_t) client->GetUserData(), (int) len, data);
		client->Send(data, len);
	});
	
	s.SetHTTPCallback([](ws28::HTTPRequest &req, ws28::HTTPResponse &res){
		std::stringstream ss;
		ss << "Hi, you issued a " << req.method << " to " << req.path << "\r\n";
		ss << "Headers:\r\n";
		
		req.headers.ForEach([&](const char *key, const char *value){
			ss << key << ": " << value << "\r\n";
		});
		
		res.send(ss.str());
	});
	
	uv_idle_t idler;
	uv_idle_init(uv_default_loop(), &idler);
	idler.data = &s;
	uv_idle_start(&idler, [](uv_idle_t *idler){
		if(quit){
			puts("Waiting for clients to disconnect, send another SIGINT to force quit");
			auto &s = *(ws28::Server*)(idler->data);
			s.StopListening();
			uv_idle_stop(idler);
		}
	});
	
	assert(s.Listen(3000));
	
	puts("Listening");
	uv_run(uv_default_loop(), UV_RUN_DEFAULT);
	puts("Clean quit");
}
