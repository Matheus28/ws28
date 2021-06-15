#ifndef H_E5DF21C793834A82B00BDD7FCD214FCC
#define H_E5DF21C793834A82B00BDD7FCD214FCC

namespace ws28 {
namespace sha1 {

    /**
     @param src points to any kind of data to be hashed.
     @param bytelength the number of bytes to hash from the src pointer.
     @param hash should point to a buffer of at least 20 bytes of size for storing the sha1 result in.
     */
    void calc(const void* src, const int bytelength, unsigned char* hash);
}
}

#endif
