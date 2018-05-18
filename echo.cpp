#include "src/Server.h"
#include <sstream>

int main(){
	ws28::Server s{8080, uv_default_loop()};
	
	static intptr_t userID = 0;
	
	s.SetClientConnectedCallback([](ws28::Client *client){
		client->SetUserData((void*) ++userID);
		printf("Client %d connected\n", (int) userID);
	});
	
	s.SetClientDisconnectedCallback([](ws28::Client *client){
		printf("Client %d disconnected\n", (int) (intptr_t) client->GetUserData());
	});
	
	s.SetClientDataCallback([](ws28::Client *client, const char *data, size_t len){
		printf("Client %d: %.*s\n", (int) (intptr_t) client->GetUserData(), (int) len, data);
	});
	
	s.SetHTTPCallback([](ws28::HTTPRequest &req, ws28::HTTPResponse &res){
		std::stringstream ss;
		ss << "Hi, you issued a " << req.method << " to " << req.path << "\r\n";
		ss << "Headers:\r\n";
		
		for(auto &p : req.headers){
			ss << p.first << ": " << p.second << "\r\n";
		}
		
		res.send(ss.str());
	});
	
	puts("Listening");
	uv_run(uv_default_loop(), UV_RUN_DEFAULT);
}
