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
    void toHexString(const unsigned char* hash, char* hexstring)
    {
        const char hexDigits[] = { "0123456789abcdef" };

        for (int hashByte = 20; --hashByte >= 0;)
        {
            hexstring[hashByte << 1] = hexDigits[(hash[hashByte] >> 4) & 0xf];
            hexstring[(hashByte << 1) + 1] = hexDigits[hash[hashByte] & 0xf];
        }
        hexstring[40] = 0;
    }
}
}
