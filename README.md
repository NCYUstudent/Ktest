# Ktest

#include <iostream>
#include <fstream>
#include "../CryptoPP/des.h"
#include "../CryptoPP/aes.h"
#include "../CryptoPP/salsa.h"
#include "../CryptoPP/panama.h"
#include "../CryptoPP/secblock.h"
#include "../CryptoPP/osrng.h"
#include "../CryptoPP/hex.h"
#include "../CryptoPP/files.h"
#include "../CryptoPP/cryptlib.h"

using namespace CryptoPP;
using namespace std;

//產生一個隨機的key存到Key.txt,keyLength為byte數
void SetRandomKeyToTXT(int keyLength) {
	fstream file;
	file.open("Key.txt", ios::out);
	AutoSeededRandomPool rng;

	if (!file) {
		cout << "SetRandomKey failed.Can't open file.\n";
		return;
	}
	else {
		cout << "New key : ";
		for (int i = 0; i < keyLength; i++) {
			byte temp = rng.GenerateByte();//產生隨機一個byte
			file << hex << (int)temp << " ";//存到Key.txt
			cout << hex << (int)temp << " ";//輸出到螢幕
		}
		cout << endl;
		return;
	}
}

//從Key.txt裡面讀Key
void SetKeyFromTXT(unsigned char gKey[], int keyLength) {
	fstream file;
	file.open("Key.txt", ios::in);

	if (!file) {
        //打不開檔案把key全部設為0
		for (int i = 0; i < keyLength; i++) {
			gKey[i] = (unsigned char)0;
		}
		return;
	}
	else {
	    //可以打開檔案,正常讀檔
		for (int i = 0; i < keyLength; i++) {
			int temp;
			file >> hex >> temp;
			gKey[i] = (unsigned char)temp;
		}
		return;
	}
}

//建立隨機IV存到TXT
void SetRandomIVToTXT(int IVLength) {
	fstream file;
	file.open("IV.txt", ios::out);
	AutoSeededRandomPool rng;

	if (!file) {
		cout << "SetRandomIV failed.Can't open file.\n";
		return;
	}
	else {
		cout << "New IV : ";
		for (int i = 0; i < IVLength; i++) {
			byte temp = rng.GenerateByte();
			file << hex << (int)temp << " ";
			cout << hex << (int)temp << " ";
		}
		cout << endl;
		return;
	}
}

//從TXT讀IV
void SetIVFromTXT(unsigned char gIV[], int IVLength) {
	fstream file;
	file.open("IV.txt", ios::in);

	if (!file) {
		for (int i = 0; i < IVLength; i++) {
			gIV[i] = (unsigned char)0;
		}
		return;
	}
	else {
		for (int i = 0; i < IVLength; i++) {
			int temp;
			file >> hex >> temp;
			gIV[i] = (unsigned char)temp;
		}
		return;
	}
}

void EncryptAES(int keyLength) {
	//get key
	unsigned char key[AES::MAX_KEYLENGTH];
	SetKeyFromTXT(key, keyLength);
	cout << "key:";
	for (int i = 0; i < keyLength; i++) {
		cout << hex << (int)key[i] << " ";
	}
	cout << endl;

	//open files
	fstream file_a, file_b;
	file_a.open("a.txt", ios::in);
	file_b.open("b.txt", ios::out);
	if (!file_a || !file_b) {
		cout << "Encrypt failed.Target or source is missing.\n";
		return;
	}

	//operation
	AESEncryption encryption_AES;//選告編碼器物件
	encryption_AES.SetKey(key, keyLength);//設置編碼器的Key

	unsigned char input[AES::BLOCKSIZE];
	unsigned char output[AES::BLOCKSIZE];

	char temp_Ch;
	int rounds = 0;
	while (file_a.get(temp_Ch)) {//一次while處理一個block
	    //讀入明文
		input[0] = temp_Ch;
		for (int i = 1; i < AES::BLOCKSIZE; i++) {
			if (file_a.get(temp_Ch)) {
				input[i] = temp_Ch;
			}
			else {
				input[i] = (unsigned char)0;
			}
		}

        //編碼
		encryption_AES.ProcessBlock(input, output);

		//寫出密文
		for (int i = 0; i < AES::BLOCKSIZE; i++) {
			file_b << hex << (int)output[i] << " ";
		}
		rounds++;
	}
	cout << dec << rounds << "rounds AES encryption complete\n";
}

void DecryptAES(int keyLength) {
	//get key
	unsigned char key[AES::MAX_KEYLENGTH];
	SetKeyFromTXT(key, keyLength);
	cout << "key:";
	for (int i = 0; i < keyLength; i++) {
		cout << hex << (int)key[i] << " ";
	}
	cout << endl;

	//open files
	fstream file_b, file_c;
	file_b.open("b.txt", ios::in);
	file_c.open("c.txt", ios::out);
	if (!file_b || !file_c) {
		cout << "Decrypt failed.Target or source is missing.\n";
		return;
	}

	//operation
	AESDecryption Decryption_AES;//宣告解碼器物件
	Decryption_AES.SetKey(key, keyLength);//設置解碼器的Key

	unsigned char input[AES::BLOCKSIZE];//密文
	unsigned char output[AES::BLOCKSIZE];//明文

	int temp_Hex;
	int rounds = 0;
	while (file_b >> hex >> temp_Hex) {//一次while處理一個block
	    //讀入密文
		input[0] = (unsigned char)temp_Hex;
		for (int i = 1; i < AES::BLOCKSIZE; i++) {
			if (file_b >> hex >> temp_Hex) {
				input[i] = (unsigned char)temp_Hex;
			}
			else {
				input[i] = (unsigned char)0;
			}
		}
        //解碼
		Decryption_AES.ProcessBlock(input, output);
        //寫出明文
		for (int i = 0; i < AES::BLOCKSIZE; i++) {
			file_c << output[i];
		}
		rounds++;
	}
	cout << dec << rounds << "rounds AES decryption complete\n";
}

void EncryptDES() {
	//get key
	unsigned char key[DES::DEFAULT_KEYLENGTH];
	SetKeyFromTXT(key, DES::DEFAULT_KEYLENGTH);
	cout << "key:";
	for (int i = 0; i < DES::DEFAULT_KEYLENGTH; i++) {
		cout << hex << (int)key[i] << " ";
	}
	cout << endl;

	//open files
	fstream file_a, file_b;
	file_a.open("a.txt", ios::in);
	file_b.open("b.txt", ios::out);
	if (!file_a || !file_b) {
		cout << "Encrypt failed.Target or source is missing.\n";
		return;
	}

	//operation
	DESEncryption encryption_DES;
	encryption_DES.SetKey(key, DES::KEYLENGTH);

	unsigned char input[DES::BLOCKSIZE];
	unsigned char output[DES::BLOCKSIZE];

	char temp_Ch;
	int rounds = 0;
	while (file_a.get(temp_Ch)) {
		input[0] = temp_Ch;
		for (int i = 1; i < DES::BLOCKSIZE; i++) {
			if (file_a.get(temp_Ch)) {
				input[i] = temp_Ch;
			}
			else {
				input[i] = (unsigned char)0;
			}
		}

		encryption_DES.ProcessBlock(input, output);

		for (int i = 0; i < DES::BLOCKSIZE; i++) {
			file_b << hex << (int)output[i] << " ";
		}
		rounds++;
	}
	cout << dec << rounds << "rounds DES encryption complete\n";
}

void DecryptDES() {
	//get key
	unsigned char key[DES::DEFAULT_KEYLENGTH];
	SetKeyFromTXT(key, DES::DEFAULT_KEYLENGTH);
	cout << "key:";
	for (int i = 0; i < DES::DEFAULT_KEYLENGTH; i++) {
		cout << hex << (int)key[i] << " ";
	}
	cout << endl;

	//open files
	fstream file_b, file_c;
	file_b.open("b.txt", ios::in);
	file_c.open("c.txt", ios::out);
	if (!file_b || !file_c) {
		cout << "Decrypt failed.Target or source is missing.\n";
		return;
	}

	//operation
	DESDecryption Decryption_DES;
	Decryption_DES.SetKey(key, DES::KEYLENGTH);
	unsigned char input[DES::BLOCKSIZE];
	unsigned char output[DES::BLOCKSIZE];

	int temp_Hex;
	int rounds = 0;
	while (file_b >> hex >> temp_Hex) {
		input[0] = (unsigned char)temp_Hex;
		for (int i = 1; i < DES::BLOCKSIZE; i++) {
			if (file_b >> hex >> temp_Hex) {
				input[i] = (unsigned char)temp_Hex;
			}
			else {
				input[i] = (unsigned char)0;
			}
		}

		Decryption_DES.ProcessBlock(input, output);
		for (int i = 0; i < DES::BLOCKSIZE; i++) {
			file_c << output[i];
		}
		rounds++;
	}
	cout << dec << rounds << "rounds DES decryption complete\n";
}

void EncryptSalsa() {
	AutoSeededRandomPool prng;
	HexEncoder encoder(new FileSink(std::cout));
	string plain, cipher;

	//get key and iv
	unsigned char key[32],iv[8];

	SetIVFromTXT(iv, 8);
	cout << "IV : ";
	for (int i = 0; i < 8; i++) {
		cout << hex << (int)iv[i] << " ";
	}
	cout << endl;

	SetKeyFromTXT(key, 32);
	cout << "key : ";
	for (int i = 0; i < 32; i++) {
		cout << hex << (int)key[i] << " ";
	}
	cout << endl;

	//open files
	fstream file_a, file_b;
	file_a.open("a.txt", ios::in);
	file_b.open("b.txt", ios::out);
	if (!file_a || !file_b) {
		cout << "Encrypt failed.Target or source is missing.\n";
		return;
	}

	//read files
	string temp_str;
	while (getline(file_a, temp_str)) {
		plain += temp_str;
		plain += '\n';
	}
	plain = plain.substr(0, plain.length() - 1);

	// Encryption object
	Salsa20::Encryption enc;
	enc.SetKeyWithIV(key, 32, iv, 8);

	StringSource ss1(plain, true, new StreamTransformationFilter(enc, new StringSink(cipher)));

	for (int i = 0; i < cipher.length(); i++) {
		file_b << hex << (int)(byte)cipher.at(i) << " ";
	}
	cout << "Salsa encryption complete\n";
}

void DecryptSalsa() {
	AutoSeededRandomPool prng;
	HexEncoder encoder(new FileSink(std::cout));
	string plain, cipher;

	//get key and iv
	unsigned char key[32], iv[8];

	SetIVFromTXT(iv, 8);
	cout << "IV : ";
	for (int i = 0; i < 8; i++) {
		cout << hex << (int)iv[i] << " ";
	}
	cout << endl;

	SetKeyFromTXT(key, 32);
	cout << "key : ";
	for (int i = 0; i < 32; i++) {
		cout << hex << (int)key[i] << " ";
	}
	cout << endl;

	//open files
	fstream file_b, file_c;
	file_b.open("b.txt", ios::in);
	file_c.open("c.txt", ios::out);
	if (!file_b || !file_c) {
		cout << "Decrypt failed.Target or source is missing.\n";
		return;
	}

	//read files
	int temp_hex;
	while (file_b >> hex >> temp_hex) {
		cipher += (char)(byte)temp_hex;
	}

	// Encryption object
	Salsa20::Decryption dec;
	dec.SetKeyWithIV(key, 32, iv, 8);

	StringSource ss1(cipher, true, new StreamTransformationFilter(dec, new StringSink(plain)));

	file_c << plain;


	cout << "Salsa decryption complete\n";
}

void EncryptPANAMA() {
	AutoSeededRandomPool prng;
	HexEncoder encoder(new FileSink(std::cout));
	string plain, cipher;

	//get key and iv
	unsigned char key[32], iv[32];

	SetIVFromTXT(iv, 32);
	cout << "IV : ";
	for (int i = 0; i < 32; i++) {
		cout << hex << (int)iv[i] << " ";
	}
	cout << endl;

	SetKeyFromTXT(key, 32);
	cout << "key : ";
	for (int i = 0; i < 32; i++) {
		cout << hex << (int)key[i] << " ";
	}
	cout << endl;

	//open files
	fstream file_a, file_b;
	file_a.open("a.txt", ios::in);
	file_b.open("b.txt", ios::out);
	if (!file_a || !file_b) {
		cout << "Encrypt failed.Target or source is missing.\n";
		return;
	}

	//read files
	string temp_str;
	while (getline(file_a, temp_str)) {
		plain += temp_str;
		plain += '\n';
	}
	plain = plain.substr(0, plain.length() - 1);

	// Encryption object
	PanamaCipher<LittleEndian>::Encryption enc;
	enc.SetKeyWithIV(key, 32, iv, 32);

	StringSource ss1(plain, true, new StreamTransformationFilter(enc, new StringSink(cipher)));

	for (int i = 0; i < cipher.length(); i++) {
		file_b << hex << (int)(byte)cipher.at(i) << " ";
	}
	cout << "Salsa encryption complete\n";
}

void DecryptPANAMA() {
	AutoSeededRandomPool prng;
	HexEncoder encoder(new FileSink(std::cout));
	string plain, cipher;

	//get key and iv
	unsigned char key[32], iv[32];

	SetIVFromTXT(iv, 32);
	cout << "IV : ";
	for (int i = 0; i < 32; i++) {
		cout << hex << (int)iv[i] << " ";
	}
	cout << endl;

	SetKeyFromTXT(key, 32);
	cout << "key : ";
	for (int i = 0; i < 32; i++) {
		cout << hex << (int)key[i] << " ";
	}
	cout << endl;

	//open files
	fstream file_b, file_c;
	file_b.open("b.txt", ios::in);
	file_c.open("c.txt", ios::out);
	if (!file_b || !file_c) {
		cout << "Decrypt failed.Target or source is missing.\n";
		return;
	}

	//read files
	int temp_hex;
	while (file_b >> hex >> temp_hex) {
		cipher += (char)(byte)temp_hex;
	}

	// Encryption object
	PanamaCipher<LittleEndian>::Decryption dec;
	dec.SetKeyWithIV(key, 32, iv, 32);

	StringSource ss1(cipher, true, new StreamTransformationFilter(dec, new StringSink(plain)));

	file_c << plain;


	cout << "PANAMA decryption complete\n";
}

int main() {
	DESEncryption encryption_DES;
	string type;
	while (1) {
		cin >> type;
		if (type == "des") {
			string instruction;
			cin >> instruction;
			if (instruction == "e") {
				EncryptDES();
			}
			else if (instruction == "d") {
				DecryptDES();
			}
			else if (instruction == "k") {
				SetRandomKeyToTXT(DES::DEFAULT_KEYLENGTH);
			}
			else {
				cout << "Invalid instruction : " << instruction << endl;
				continue;
			}
		}
		else if (type == "aes") {
			string instruction;
			cin >> instruction;

			string keyLength_str;
			int keyLength = 16;
			if (instruction == "e" || instruction == "d" || instruction == "k") {
				cin >> keyLength_str;
				if (keyLength_str == "16" || keyLength_str == "24" || keyLength_str == "32") {
					keyLength = stoi(keyLength_str, nullptr, 10);
				}
				else {
					cout << "Invalid key length.\n";
					continue;
				}
			}

			if (instruction == "e") {
				EncryptAES(keyLength);
			}
			else if (instruction == "d") {
				DecryptAES(keyLength);
			}
			else if (instruction == "k") {
				SetRandomKeyToTXT(keyLength);
			}
			else {
				cout << "Invalid instruction : " << instruction << endl;
				continue;
			}
		}
		else if (type == "salsa") {
			string instruction;
			cin >> instruction;
			if (instruction == "e") {
				EncryptSalsa();
			}
			else if (instruction == "d") {
				DecryptSalsa();
			}
			else if (instruction == "k") {
				SetRandomKeyToTXT(Salsa20::MAX_KEYLENGTH);
			}
			else if (instruction == "iv") {
				SetRandomIVToTXT(8);
			}
			else {
				cout << "Invalid instruction : " << instruction << endl;
				continue;
			}
		}
		else if (type == "panama") {
			string instruction;
			cin >> instruction;
			if (instruction == "e") {
				EncryptPANAMA();
			}
			else if (instruction == "d") {
				DecryptPANAMA();
			}
			else if (instruction == "k") {
				SetRandomKeyToTXT(32);
			}
			else if (instruction == "iv") {
				SetRandomIVToTXT(32);
			}
			else {
				cout << "Invalid instruction : " << instruction << endl;
				continue;
			}
		}
		else if (type == "quit") {
			break;
		}
		else {
			cout << "Invalid type : " << type << endl;
		}


	}

	system("pause");
	return 0;
}
