#ifndef H_39B56032251A44728943666BD008D047
#define H_39B56032251A44728943666BD008D047

#include <cstring>
#include <vector>
#include <utility>

namespace ws28 {
	class Client;
	
	class RequestHeaders {
	public:
		void Set(const char *key, const char *value){
			m_Headers.push_back({ key, value });
		}
		
		template<typename F>
		void ForEachValueOf(const char *key, const F &f) const {
			for(auto &p : m_Headers){
				if(strcmp(p.first, key) != 0) continue;
				f(p.second);
			}
		}
		
		const char* Get(const char *key) const {
			for(auto &p : m_Headers){
				if(strcmp(p.first, key) != 0) continue;
				return p.second;
			}
			
			return nullptr;
		}
		
		template<typename F>
		void ForEach(const F &f) const {
			for(auto &p : m_Headers){
				f(p.first, p.second);
			}
		}
		
	private:
		std::vector<std::pair<const char*, const char*>> m_Headers;
		
		friend class Client;
		friend class Server;
	};
	
}

#endif
