#ifndef H_39B56032251A44728943666BD008D047
#define H_39B56032251A44728943666BD008D047

#include <cstring>
#include <map>

namespace ws28 {
	namespace detail {
		template<typename T>
		struct pair_range {
			pair_range(const std::pair<T, T> &p) : p(p){}
			
			T begin(){ return p.first; }
			T end(){ return p.second; }
			
			std::pair<T, T> p;
		};
		
		bool equalsi(const char *a, const char *b);
		
		struct multimap_compare {
			inline bool operator()(const char *a, const char *b) const {
				return std::lexicographical_compare(a, a + strlen(a), b, b + strlen(b));
			}
		};
		
		class multihash : public std::multimap<const char*, const char*, multimap_compare> {
		public:
			pair_range<iterator> equal_range_ex(const char *key){
				return pair_range<iterator>(equal_range(key));
			}
			
			pair_range<const_iterator> equal_range_ex(const char *key) const{
				return pair_range<const_iterator>(equal_range(key));
			}
		};
	}
	
	class Client;
	
	// This is a bit ugly, but we optimize to not use the hash table to store some headers that are almost always gonna be there
	// It also contains a quirk: if the user sends multiple values for a header we optimize for, we only keep the latest one
	class RequestHeaders {
	public:
		#define XX \
			X("upgrade", m_hUpgrade) \
			X("connection", m_hConnection) \
			X("host", m_hHost) \
			X("origin", m_hOrigin) \
			X("user-agent", m_hUserAgent) \
			X("sec-websocket-key", m_hSecWebSocketKey) \
			X("sec-websocket-version", m_hSecWebSocketVersion) \
			
		void Set(const char *key, const char *value){
			#define X(str, variable) if(strcmp(key, str) == 0){ variable = value; return; }
			XX
			#undef X
			
			m_Headers.insert({ key, value });
		}
		
		template<typename F>
		void ForEachValueOf(const char *key, const F &f) const {
			#define X(str, variable) if(strcmp(key, str) == 0){ f(variable); return;}
			XX
			#undef X
			
			for(auto &p : m_Headers.equal_range_ex(key)){
				f(p.second);
			}
		}
		
		template<typename F>
		void ForEach(const F &f) const {
			#define X(str, variable) if(variable) f(str, variable);
			XX
			#undef X
			
			for(auto &p : m_Headers){
				f(p.first, p.second);
			}
		}
		
	private:
		#define X(str, variable) const char *variable = nullptr;
		XX;
		#undef X
		
		detail::multihash m_Headers;
		
		#undef XX
		
		friend class Client;
		friend class Server;
	};
	
}

#endif