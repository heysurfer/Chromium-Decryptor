#ifndef _BASE64_H_
#define _BASE64_H_

#include <vector>
#include <string>
typedef unsigned char BYTE;

class Base64
{
public:
    static std::string encode(const std::string& binaryText);
    static std::string decode(const std::string& base64Text);
};

#endif