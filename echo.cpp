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
	
	// I recommend against setting these limits, they're way too high and allow easy DDoSes.
	// Use the default settings. These are just here to pass tests
	s.SetMaxMessageSize(256 * 1024 * 1024); // 256 MB
	s.SetMaxMessageFrames(1024 * 1024); // 1 million
	
	
	s.SetClientConnectedCallback([](ws28::Client *client){
		client->SetUserData((void*) ++userID);
		//printf("Client %d connected\n", (int) userID);
	});
	
	s.SetClientDisconnectedCallback([](ws28::Client *client){
		//printf("Client %d disconnected\n", (int) (intptr_t) client->GetUserData());
	});
	
	s.SetClientDataCallback([](ws28::Client *client, const char *data, size_t len, int opcode){
		//printf("Client %d: %.*s\n", (int) (intptr_t) client->GetUserData(), (int) len, data);
		client->Send(data, len, opcode);
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
	
	uv_timer_t timer;
	uv_timer_init(uv_default_loop(), &timer);
	timer.data = &s;
	uv_timer_start(&timer, [](uv_timer_t *timer){
		if(quit){
			puts("Waiting for clients to disconnect, send another SIGINT to force quit");
			auto &s = *(ws28::Server*)(timer->data);
			s.StopListening();
			uv_timer_stop(timer);
			uv_close((uv_handle_t*) timer, nullptr);
		}
	}, 10, 10);
	
	assert(s.Listen(3000));
	
	puts("Listening");
	uv_run(uv_default_loop(), UV_RUN_DEFAULT);
	assert(uv_loop_close(uv_default_loop()) == 0);
	puts("Clean quit");
}
