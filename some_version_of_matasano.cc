/*
 * ===========================================================================
 *
 *       Filename:  matasano.cc
 *
 *    Description:  This file will contain all the MATASANO crypto
 *                  problems/solutions
 *
 *        Version:  1.0
 *        Created:  05/21/2013 02:20:12 PM
 *       Revision:  none
 *       Compiler:  gcc
 *
 *         Author:  Dr. Sadanandan (GS ZZ9 Plural Zα), grep@whybenormal.org
 *        Company:  
 *
 * ===========================================================================
 */

#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>

typedef unsigned char unch;

namespace Utils
{
	std::string s64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	void ThreeUncharToFour6BitChar(unch * unchar, char * sixbitchar)
	{
		sixbitchar[0] = (unchar[0] & 0xfc) >> 2;
		sixbitchar[1] = ((unchar[0] & 0x03) << 4) + ((unchar[1] & 0xf0) >> 4);
		sixbitchar[2] = ((unchar[1] & 0x0f) << 2) + ((unchar[2] & 0xc0) >> 6);
		sixbitchar[3] = unchar[2] & 0x3f;
	}

	bool IsHexChar(char c)
	{
		return (('0' <= c) && (c <= '9')) ||
			(('a' <= c) && (c <= 'f')) ||
			(('A' <= c) && (c <= 'F'));
	}

	unch HexVal(char c)
	{
		if (('0' <= c) && (c <= '9')) return c - '0';
		if (('a' <= c) && (c <= 'f')) return c - 'a' + 10;
		if (('A' <= c) && (c <= 'F')) return c - 'A' + 10;
		throw "Check whether it is hex digit, before looking for value";
	}

	bool IsHexString(std::string str)
	{
		for( unsigned int i = 0 ; i < str.length() ; i += 1 )
			if (!IsHexChar(str[i]))
				return false;
		return true;
	}


	unch * StringToBin(std::string str, int &newlen)
	{
		unch * arr = new unch[str.length()];
#ifdef RAND1
		for( int i = 0 ; i < str.length ; i += 1 )
			arr[i] = str[i];
#else
		memcpy(arr, str.c_str(), str.length());
#endif 
		newlen = str.length();
		return arr;		
	}

	unch * HexToBin(std::string str, int &newlen)
	{
		if (!IsHexString(str))
		{
			std::cerr << "Non hexstring, abort" << std::endl;
			return NULL;
		}

		if ((str.length() % 2) != 0)
		{
			std::cerr << "We'll add a ZERO at the end" << std::endl;
			str.append("0");
		}

		newlen = str.length() / 2;
		unch * arr = new unch[newlen + 1];
		arr[newlen] = 0;

		for( unsigned int i = 0 ; i < str.length() ; i += 2 )
		{
			int firstnibble = HexVal(str[i]);
			int secondnibble = HexVal(str[i+1]);
			arr[i/2] = (unch) ((firstnibble << 4) | secondnibble);
		}

		return arr;		
	}

	std::string BinToBase64(unch * input_bin_array, int len)
	{
		std::string outstring;
		int read_end;
		char temp[4];

		for( read_end = 0 ; read_end <= len - 3 ; read_end += 3 )
		{
			ThreeUncharToFour6BitChar(input_bin_array + read_end, temp);
			for( int i = 0 ; i < 4 ; i += 1 )
				outstring += s64[temp[i]];
		}

		int remains = len - read_end;
		if (remains != 0)
		{
			if ((remains < 1) || (remains > 2))
				throw "wrong counting";

			// take all from input, and fill rest with zero
			unch endarray[3];
			endarray[0] = input_bin_array[read_end++]; // there is at least one byte
			endarray[1] = (remains == 2) ? input_bin_array[read_end++] : 0; // if there's a second one.
			endarray[2] = 0; // always zero.

			ThreeUncharToFour6BitChar(endarray, temp);
			for( int i = 0 ; i < 4 ; i += 1 )
				outstring += (i < (remains + 1)) ? s64[temp[i]] : '=';
		}
		return outstring;
	}

	unch * Base64ToBin(std::string str, int& len)
	{
		int input_length = str.length();

		int outbin_length = input_length * 3 / 4 /* - fx(#'=') */;
		unch * outbin = new unch[outbin_length];

		len = 0;
		for(int read_end = 0 ; read_end < input_length ; read_end += 4 )
		{
			char c;
			if ((c = s64.find(str[read_end])) == -1) 
				break;

			outbin[len] = c << 2;

			if ((c = s64.find(str[read_end + 1])) == -1) 
				break;

			outbin[len++] |= ((c & 0x30) >> 4);
			outbin[len] = ((c & 0x0f) << 4);

			if ((c = s64.find(str[read_end + 2])) == -1) 
				break;

			outbin[len++] |= ((c & 0x3c) >> 2);
			outbin[len] = ((c & 0x03) << 6);

			if ((c = s64.find(str[read_end + 3])) == -1) 
				break;

			outbin[len++] |= c;
		}
		return outbin;
	}

	unch * BinXOR(unch * bytesA, unch * bytesB, int len)
	{
		if (bytesA == NULL)
			throw "First set is NULL\n";
		if (bytesB == NULL)
			throw "Second set is null\n";
		if (len < 0)
			throw "Length cannot be negative\n";

		if (len == 0)
			return NULL;

		unch * xorred = new unch[len];
		unch * tmp = xorred;
		while (len--)
		{
			*tmp = *bytesA ^ *bytesB;		
			tmp++;
			bytesA++;
			bytesB++;
		}
		return xorred;
	}

	void PrintBin(unch * arr, int len, bool prefix = false)
	{
		if ((arr == NULL) || (len < 1))
			return;

		if (prefix) std::cout << "0x";
		for( int i = 0 ; i < len ; i += 1 )
			std::cout << std::setw(2) << std::setfill('0') << std::hex << (int) arr[i];
		std::cout << std::endl;
	}

	unch MostFrequentByte(unch * bytes, int len)
	{
		if ((bytes == NULL) || (len <= 0))
		{
			std::cout << "Nothing to lookf for!"  << std::endl;
			throw -1;
		}

		int frqncy[256] = {0,};
		while(len--)
			frqncy[*bytes++]++;

		int index = -1, max = -1;
		for( int i = 0 ; i < 256 ; i += 1 )
		{
			if (frqncy[i] > max)
			{
				index = i;
				max = frqncy[i];
			}
		}

		return (unch) index;
	}

	double ValidSentenceProbability(const std::string txt)
	{
		if (txt.length() == 0)
			return 1.0;

		double sum = 0;
		for( unsigned int i = 0 ; i < txt.length() ; i += 1 )
		{
			int c = txt[i];
			if (!isascii(c))
				sum += 0.01;
			else if (isalpha(c) || isblank(c))
				sum += 1;
			else if (ispunct(c))
				sum += 0.33;
			else if (isdigit(c))
				sum += 0.50;
			else 
				sum += 0.10;
		}
		return sum / txt.length();		
	}
	
	unch * RepeatKeyEncrypt(unch * txt, int txtlen, unch * key, int keylen)
	{
		if ((txt == NULL) || (txtlen <= 0))
		{
			std::cerr << "Empty plain text" << std::endl;
			throw "empty plain text";
		}

		if ((key == NULL) || (keylen <= 0))
		{
			std::cerr << "Empty plain key" << std::endl;
			throw "empty plain key";
		}

		unch * cipher = new unch[txtlen];
		for( int i = 0 ; i < txtlen ; i += 1 )
		{
			cipher[i] = txt[i] ^ key[i%keylen];
		}
		return cipher;
	}

	unsigned int SetBitCount(unch v)
	{
		// count the number of bits set in v
		unsigned int c; // c accumulates the total bits set in v
		for (c = 0; v; c++)
		{
			v &= v - 1; // clear the least significant bit set
		}
		return c;
	}
}


enum Representation
{
	HEXSTRING,
	BASE64STR,
	PLAINTEXT,
};

class Data
{
	private:
		unch * m_data;// = NULL;
		int m_data_sz;// = 0;
		std::string m_name;

	public:
		Data(std::string str_rep, Representation representation)
		{
			switch (representation)
			{
				case HEXSTRING:
					m_name = "HEXSTRING";
					m_data = Utils::HexToBin(str_rep, m_data_sz);
					break;

				case BASE64STR:
					m_name = "BASE64STR";
					m_data = Utils::Base64ToBin(str_rep, m_data_sz);
					break;

				case PLAINTEXT:
					m_name = "PLAINTEXT";
					m_data = Utils::StringToBin(str_rep, m_data_sz);
					break;

				default:
					throw "Unknown format\n";
			}
		}

		Data(unch * data, int data_len)
		{
			m_name = "BINARY";
			if ((data == NULL) || (data_len <= 0))
			{
				std::cout <<  "Cannot create non-existing data" << std::endl;
				throw "Cannot create non-existing data\n";
			}

			m_data = new unch[data_len];
			memcpy(m_data, data, data_len);
			m_data_sz = data_len;		
		}

		~Data()
		{
			if (m_data != NULL)
			{
//				std::cout << "Deleting data: " << m_name << std::endl;
				delete m_data;
				m_data = NULL;
			}
		}

		unch * Content()
		{
			return m_data;
		}

		int Size()
		{
			return m_data_sz;
		}

		unch MostFrequentByte(unsigned int start = 0, unsigned int len = 0)
		{
			if (start >= (unsigned int) m_data_sz)
			{
				std::cerr << "Looking past the end is not possible" << std::endl;
				throw -1;
			}
			len = (len == 0) ? m_data_sz : len; // if zero, make it full.
			len = ((start + len) > (unsigned int) m_data_sz) ? (m_data_sz - start) : len; // if too long, shorten.
			return Utils::MostFrequentByte(m_data + start, len);
		}

		friend Data operator^ (Data &one, Data &other);
		friend bool operator== (Data &data1, Data &data2);
		friend std::ostream& operator<<(std::ostream &out, Data &data);

		Data EncryptWithKey(Data &Key)
		{
			unch * encrypted = Utils::RepeatKeyEncrypt(m_data, m_data_sz, Key.Content(), Key.Size()); 
			Data dEncry = Data(encrypted, m_data_sz);
			delete encrypted;
			return dEncry;
		}

		Data Transpose(int size, unsigned int &blocksz)
		{
			blocksz = m_data_sz / size;
			unch temp[m_data_sz];
			int end = 0;

			for( int j = 0 ; j < size ; j += 1 )
			{
				for( int i = 0 ; i < m_data_sz ; i += 1 )
				{
					std::cout << i << " " << j << " " << ((i*size) + j) << " " << end << std::endl;
					temp[end++] = m_data[(i * size) + j];					
				}				
			}
			
			blocksz = m_data_sz/size;

			Data transposed = Data(temp, m_data_sz);
			return transposed;
		}

		unsigned int BitCount()
		{
			unsigned int count = 0;
			for( int i = 0 ; i < m_data_sz ; i += 1 )
				count += Utils::SetBitCount(m_data[i]);
			return count;
		}
};

unsigned int HammingDist(Data &data1, Data &data2)
{
	Data diff = data1 ^ data2;
	return diff.BitCount();
}

bool operator== (Data &data1, Data &data2)
{
	if (data1.m_data_sz == data2.m_data_sz)
		return memcmp(data1.m_data, data2.m_data, data1.m_data_sz) == 0;
	return false;
}

std::ostream& operator<<(std::ostream &out, Data &data)
{
	out << "++++++++++++++++++++++++++++++" << std::endl;
	out << data.m_name 	<< " (Size: " << data.m_data_sz << ")" << std::endl;
	out << "Hex: ";
	for( int i = 0 ; i < data.m_data_sz; i += 1 )
		out  << std::setw(2) << std::setfill('0') << std::hex << (int) data.m_data[i];
	out << std::dec << std::endl;
	out << "Base64 : " << Utils::BinToBase64(data.m_data, data.m_data_sz) << std::endl;
	out << "------------------------------" << std::endl;
	return out;
}

Data operator^ (Data &one, Data &other)
{
	if (one.m_data_sz != other.m_data_sz)
	{
		std::cout << "Unmatching sizes, cannot do it" << std::endl;
		throw -1;
	}
	unch * xorred = Utils::BinXOR(one.m_data, other.m_data, one.m_data_sz);
	Data dXorred = Data(xorred, one.m_data_sz);
	delete xorred;
	return dXorred;
}

std::string DecryptCeaser(Data &data, unch guess, int start, int end, bool onlyascii = true)
{
	std::string txt;
	unch * content = data.Content();
	end = (end < data.Size()) ? end : data.Size();
	for( int i = start ; i < end ; i += 1 )
	{
		unch c = content[i] ^ guess;
		if (onlyascii && !isascii((int)c))
			return "";
		txt += (char) c;
	}
	return txt;
}

std::string Int2Str(int number, bool printchar = false)
{
	std::stringstream ss;
	ss << "0x" << std::hex << number;
	if (isascii(number))
		ss << ": " << (char) number << ": ";
	return ss.str();
}

std::string AllAsciiString()
{
	std::string aas;
	for( int i = 1 ; i < 256 ; i += 1 )
		if(isascii(i))
			aas += (char)i;
	return aas;	
}

std::map<std::string, double> DecryptCeaser(Data &data, int blksz=0, double threshold=0.85)
{
	using namespace std;
	map<string, double> mymap;
	string freqs = " eEaAoOiItTuUhH" + AllAsciiString();
	blksz = (blksz == 0) ? data.Size() : blksz; // if zero, take full.
	int rend = 0;
	while(rend < data.Size())
	{
		unch most = data.MostFrequentByte(rend, blksz);
		for(unsigned int i = 0 ; i < freqs.length() ; i += 1 )
		{
			unch freq = freqs[i];
			unch guess = freq ^ most;

			string txt = DecryptCeaser(data, guess, rend, blksz);
			if (txt.length() == 0)
				continue;

			double probability = Utils::ValidSentenceProbability(txt);
			if (probability	>= threshold)
			{
				string outstring = "Blk: " + Int2Str(rend/blksz) + Int2Str((int) guess, true) + string(txt);
				mymap.insert(pair<string, double>(outstring, probability));
			}
		}
		rend += blksz;
	}
	return mymap;
}

bool DecryptCeaser(std::string hexData, double threshold = 0.85)
{
	using namespace std;
	if (hexData.length() == 0)
		return false;
	Data satz = Data(hexData, HEXSTRING);
	map<string, double> strings = DecryptCeaser(satz, threshold);
	map<string, double>::iterator it;
	if (strings.size() <= 0) 
		return false;
	cout << "Decrypting: " << hexData << endl;
	cout.precision(5);
	for(it = strings.begin() ; it != strings.end() ; ++it)
		  cout << it->second << " => " << it->first << endl;
	return true;
}

bool TestHamming()
{
	Data test = Data("this is a test", PLAINTEXT);
	Data wokka = Data("wokka wokka!!!", PLAINTEXT);
	return (HammingDist(test, wokka) == 37);
}

double KeySizeNormalisation(Data &cipher, unsigned int keysize, int rounds=1)
{
	using namespace std;
	if (keysize == 0)
	{
		cerr << "You don't want to check keysize zero" << endl;
		return 999;
	}

	if ((rounds * 2 * keysize) > cipher.Size())
	{
		cerr << "You can't have that long a key!" << endl;
		throw -1;
	}

	unch first[keysize], second[keysize];
	unch * data = cipher.Content();
	double hdistsum = 0.0;
	int start = 0;
	while (start < (rounds * 2 * keysize))
	{
		memcpy(first, data + start, keysize);
		memcpy(second, data + start + keysize, keysize);
		Data dfirst = Data(first, keysize);
		Data dsecond = Data(second, keysize);
		hdistsum += HammingDist(dfirst, dsecond);
		start += (keysize * 2);
	} 

	if (start == 0)
	{
		cerr << "You need to loop at least once" << endl;
		throw -1;
	}
		
	double result = (hdistsum / (double) rounds) / (double) keysize;
	cout << "##: " << rounds << "; Σ: " << hdistsum << "; Size: " << keysize << "; μ: " << result << endl;
	return result;
}

unsigned int FindKeySize(Data &cipher, unsigned int start = 2, unsigned int end = 40)
{
	unsigned int keysize = 0;
	double minnormalised = 9; // max is actually 8, even if all bits are different.
	for(unsigned int i = start ; i <= end ; i += 1 )
	{
		double normalised = KeySizeNormalisation(cipher, i);
		std::cout.precision(5);
		if (normalised < minnormalised)
		{
			keysize = i;
			minnormalised = normalised;
//			std::cout << "Size: " << keysize << "; Normalised val: " << minnormalised << std::endl;
		}
		else if (normalised == minnormalised)
			std::cerr << "Two keys, with same result? No!" << std::endl;
	}
	std::cout << "Size: " << keysize << "; Normalised val: " << minnormalised << std::endl;
	return keysize;
}

bool DecryptRepeatXOR(Data &cipher, double threshold = 0.85)
{
	using namespace std;
	unsigned int keysizeguess = FindKeySize(cipher);
	unsigned int blocksize = 0;
	Data transpose = cipher.Transpose(keysizeguess, blocksize);
	map<string, double> strings = DecryptCeaser(transpose, blocksize, threshold);

	if (strings.size() <= 0) 
	{
		cout << "Nothing to print" << endl;
		//			return false;
	}

	//	cout << "Decrypting: " << cipher << endl;
	cout.precision(5);
	map<string, double>::iterator it;
	for(it = strings.begin() ; it != strings.end() ; ++it)
		cout << it->first << " => " << it->second << endl;
	return true;
}

bool Problem06()
{
	using namespace std;
	// test whether we are ready with HammingDist()
	if (!TestHamming())
	{
		cerr << "Hamming distance isn't ready" << endl;
		return false;
	}

	// get each input.
	ifstream inf("problem06.dat");

	if(!inf)
	{
		cerr << "Input file couldn't be opened" << endl;
		return false;
	}

	string line;
	inf >> line;

	Data xx = Data("AABBCCDDEEFF0011", HEXSTRING);
	cout << xx << endl;

	unsigned int junk = 0;
	Data yy = xx.Transpose(2, junk);
	cout << yy << endl;

//	Data cipher = Data(line, BASE64STR);
//	return DecryptRepeatXOR(cipher);
}

bool Problem05()
{
	using namespace std;
	Data input = Data("Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal", PLAINTEXT);
	Data key   = Data("ICE", PLAINTEXT);
	Data cipher = input.EncryptWithKey(key);
	Data expected = Data("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", HEXSTRING);
	return (cipher == expected);
}

#define THRESHOLD 0.96
bool Problem04()
{
	using namespace std;
	ifstream inf("problem04.dat");

	if(!inf)
	{
		cerr << "Input file couldn't be opened" << endl;
		return false;
	}

	bool haveit = false;
	while(inf)
	{
		string line;
		inf >> line;
		haveit |= DecryptCeaser(line, THRESHOLD);
	}
	return haveit;
}

bool Problem03()
{
	using namespace std;
	DecryptCeaser("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736", THRESHOLD);
	return true;
}

bool Problem02()
{
	Data data1 = Data("1c0111001f010100061a024b53535009181c", HEXSTRING);
	Data data2 = Data("686974207468652062756c6c277320657965", HEXSTRING);
	Data data3 = data1 ^ data2;

	Data expected = Data("746865206b696420646f6e277420706c6179", HEXSTRING);
	return (data3 == expected);
}

bool Problem01()
{
	using namespace std;
	Data data1 = Data("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t", BASE64STR);
	Data data2 = Data("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d", HEXSTRING);
	Data dresult = Data("000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", HEXSTRING);
	Data data3 = data1 ^ data2;

//	cout << data1 << data2 << data3 << endl;
	return (data3 == dresult);
}

bool Problem00()
{
	std::cout << "There is no zeroth problem" << std::endl;
	return true;
}

typedef bool (*problem_solver)();
bool ProblemXX(int prob)
{
	using namespace std;
	problem_solver problem_solvers[48] = {Problem00, Problem01, Problem02, 
		                                  Problem03, Problem04, Problem05, 
										  Problem06, NULL,};
	cout << "Starting Problem: " << prob << endl;
	if (problem_solvers[prob] == NULL)
	{
		cout << "Not possible, not defined yet" << endl;
		return false;
	}

	bool (*foo)() = problem_solvers[prob];	
	bool result;
	if ((result = foo()))
		cout << "Successful" << endl << endl;
	else 
		cout << "Failed" << endl;
	return result;
}

int main(int argc, char *argv[])
{
	for( int i = 6 ; i < 48 ; i += 1 )
		if(!ProblemXX(i))
			break;
	return 0;
}


/*
Hello!

Sorry if you're getting this problem set for the second time. We're
still fine-tuning our process, and there are a few kinks to work out.

That being said: enclosed are the cryptography challenges you
requested.

To be clear, this is a subset comprising the first eight problems. You
can get the second set by solving these first. Feel free to send us
solutions in the language of your choice along with answers in
comments or the body of your email.

If you get stuck or need clarification on something, don't hesitate to
ask! We're happy to help.

THE RULES AND THEY ARE SOMEWHAT IMPORTANT:

* Please do not share this with anyone or post solutions online. If you
have any friends who would like to participate, send them our way and
we will set them up.

* When you mail your solutions, please CC responses@matasanocryptopals.com.

* Please prefix the subject of your mail with RESPONSE:.

// ------------------------------------------------------------

1. Convert hex to base64 and back.

The string:

  49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d

should produce:

  SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t

Now use this code everywhere for the rest of the exercises. Here's a
simple rule of thumb:

  Always operate on raw bytes, never on encoded strings. Only use hex
  and base64 for pretty-printing.

// ------------------------------------------------------------

2. Fixed XOR

Write a function that takes two equal-length buffers and produces
their XOR sum.

The string:

 1c0111001f010100061a024b53535009181c

... after hex decoding, when xor'd against:

 686974207468652062756c6c277320657965

... should produce:

 746865206b696420646f6e277420706c6179

// ------------------------------------------------------------

3. Single-character XOR Cipher

The hex encoded string:

      1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736

... has been XOR'd against a single character. Find the key, decrypt
the message.

Write code to do this for you. How? Devise some method for "scoring" a
piece of English plaintext. (Character frequency is a good metric.)
Evaluate each output and choose the one with the best score.

Tune your algorithm until this works.

// ------------------------------------------------------------

4. Detect single-character XOR

One of the 60-character strings at:

  https://gist.github.com/3132713

has been encrypted by single-character XOR. Find it. (Your code from
#3 should help.)

// ------------------------------------------------------------

5. Repeating-key XOR Cipher

Write the code to encrypt the string:

  Burning 'em, if you ain't quick and nimble
  I go crazy when I hear a cymbal

Under the key "ICE", using repeating-key XOR. It should come out to:

  0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f

Encrypt a bunch of stuff using your repeating-key XOR function. Get a
feel for it.

// ------------------------------------------------------------

6. Break repeating-key XOR

The buffer at the following location:

 https://gist.github.com/3132752

is base64-encoded repeating-key XOR. Break it.

Here's how:

a. Let KEYSIZE be the guessed length of the key; try values from 2 to
(say) 40.

b. Write a function to compute the edit distance/Hamming distance
between two strings. The Hamming distance is just the number of
differing bits. The distance between:

  this is a test

and:

  wokka wokka!!!

is 37.

c. For each KEYSIZE, take the FIRST KEYSIZE worth of bytes, and the
SECOND KEYSIZE worth of bytes, and find the edit distance between
them. Normalize this result by dividing by KEYSIZE.

d. The KEYSIZE with the smallest normalized edit distance is probably
the key. You could proceed perhaps with the smallest 2-3 KEYSIZE
values. Or take 4 KEYSIZE blocks instead of 2 and average the
distances.

e. Now that you probably know the KEYSIZE: break the ciphertext into
blocks of KEYSIZE length.

f. Now transpose the blocks: make a block that is the first byte of
every block, and a block that is the second byte of every block, and
so on.

g. Solve each block as if it was single-character XOR. You already
have code to do this.

e. For each block, the single-byte XOR key that produces the best
looking histogram is the repeating-key XOR key byte for that
block. Put them together and you have the key.

// ------------------------------------------------------------

7. AES in ECB Mode

The Base64-encoded content at the following location:

    https://gist.github.com/3132853

Has been encrypted via AES-128 in ECB mode under the key

    "YELLOW SUBMARINE".

(I like "YELLOW SUBMARINE" because it's exactly 16 bytes long).

Decrypt it.

Easiest way:

Use OpenSSL::Cipher and give it AES-128-ECB as the cipher.

// ------------------------------------------------------------

8. Detecting ECB

At the following URL are a bunch of hex-encoded ciphertexts:

   https://gist.github.com/3132928

One of them is ECB encrypted. Detect it.

Remember that the problem with ECB is that it is stateless and
deterministic; the same 16 byte plaintext block will always produce
the same 16 byte ciphertext.

// ------------------------------------------------------------

*/
