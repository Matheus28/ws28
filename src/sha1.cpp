#include <openssl/sha.h>
#include "sha1.h"

namespace ws28 {
namespace sha1 {
    void calc(const void* src, const int bytelength, unsigned char* hash)
    {
        SHA_CTX sha1;
        SHA1_Init(&sha1);
        SHA1_Update(&sha1, src, bytelength);
        SHA1_Final(hash, &sha1);

    }
}
}
