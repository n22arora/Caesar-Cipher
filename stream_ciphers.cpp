 //============================================================================
// Name        : Project-2.cpp
// Author      : 
// Version     :
// Copyright   : Your copyright notice
// Description : Hello World in C++, Ansi-style
//============================================================================

#include <iostream>
#include <string>
#include <cmath>

char *encode( char *plaintext, unsigned long key );
char *decode( char *ciphertext, unsigned long key );

#ifndef MARMOSET_TESTING
int main();
#endif

#ifndef MARMOSET_TESTING
int main()
{
	char str0[]{ "study" };
	char str1[]{ "A Elbereth Gilthoniel\nsilivren penna miriel\n"
	"o menel aglar elenath!\nNa-chaered palan-diriel\n"
	"o galadhremmin ennorath,\nFanuilos, le linnathon\n"
	"nef aear, si nef aearon!" }; // [1]

	std::cout << "\"" << str0 << "\"" << std::endl;
	char *ciphertext{ encode( str0, 3408 ) };

	std::cout << "\"" << ciphertext << "\"" << std::endl;
	char *plaintext{ decode( ciphertext, 3408 ) };
	std::cout << "\"" << plaintext << "\"" << std::endl;

	delete[] plaintext;
	plaintext = nullptr;
	delete[] ciphertext;
	ciphertext = nullptr;

	std::cout << "\"" << str1 << "\"" << std::endl;
	ciphertext = encode( str1, 51323 );

	std::cout << "\"" << ciphertext << "\"" << std::endl;
	plaintext = decode( ciphertext, 51323 );
	std::cout << "\"" << plaintext << "\"" << std::endl;

	delete[] plaintext;
	plaintext = nullptr;
	delete[] ciphertext;
	ciphertext = nullptr;

std::cout<<std::endl;
return 0;
}
#endif

char *encode( char *plaintext, unsigned long key )
{
	std::size_t charlen{};
	std::size_t num_of_additional_null{};
	unsigned int p=0;
	while(plaintext[p] != '\0')
	{
		charlen++;
		p++;           // number of characters in plaintext excluding null character
	}



	unsigned int blocks_of_4 = (std::ceil(charlen/4.0));
	std::size_t h = (charlen%4) ;
	std::size_t size_of_xor_a{0};
	if(h != 0)
	{
	num_of_additional_null = 4-h;
	size_of_xor_a = charlen + num_of_additional_null;
	}
	else
	{
		size_of_xor_a = charlen;
	}
	unsigned char xor_a[size_of_xor_a];
	unsigned temp_plaintext[size_of_xor_a];
	for(std::size_t y=0; plaintext[y]!=0 ; y++)
	{
		temp_plaintext[y] = plaintext[y];
	}
	std::size_t size_of_armor= (5*blocks_of_4) + 1;

	std::size_t q{0};
	if(charlen %4 !=0)
	{
	for(q=charlen ; q<size_of_xor_a ; q++)
	{
		xor_a[q] = '\0';
		temp_plaintext[q] = '\0';
	}
	}
	unsigned int k{0};
	unsigned int s[256];
	for(k=0; k<256 ; k++)
	{
		s[k]=k;
	}
	unsigned int i{0}, j{0};
	unsigned int tmp{0}, m=0;
	for(m=0; m<256 ; m++)
	{
		k = i%64;
		j = (j + s[i] + ((key>>k)&1L))%256;
		tmp = s[i];
		s[i]= s[j];
		s[j] = tmp;
		i= (i+1)%256;
	}


	unsigned int tmp1{0};
	p =0;
	unsigned int r{0} , R{0};

	while(p<size_of_xor_a)
	{
		i = (i+1)%256;
		j = (j + s[i])%256;
		tmp1  = s[i];
		s[i] = s[j];
		s[j] = tmp1;
		r = (s[i] + s[j])%256;
		R = s[r];
		xor_a[p] = R^(temp_plaintext[p]);
		p++;
	}

	char *a_armor = new char[size_of_armor];
	a_armor[size_of_armor-1]= '\0';
	unsigned int sum = 0;
	int f=0;
	int l_limit=0;
	int u_limit=0;
	unsigned mod_85{0};
	unsigned add_33{0};
	std::size_t b=0;
	for (std::size_t u= 0 ; u<size_of_xor_a ; u= u+4)
	{
		l_limit = f;
		u_limit = f+5;
		sum = xor_a[u];
		mod_85=0;
		add_33= 0;
		for( b=u+1 ; b<u+4 ; b++)
		{
			sum = sum<<8;
			sum = sum + xor_a[b];
		}
		while((u_limit-1>=l_limit))
		{
			mod_85= sum%85;
			sum = sum/85;
			add_33 = mod_85 +33;
			a_armor[u_limit-1] = char(add_33);
			u_limit--;
			f++;
		}

	}
	return a_armor;
}




char *decode(char *ciphertext, unsigned long key)
{
	std::size_t charlen{0};
	std::size_t p{0};
	while(ciphertext[p]!= '\0')
	{
		charlen++;   // counts number of characters in ciphertext excluding null character
		p++;
	}
	std::size_t blocks_of_5 = (charlen/5);
	std::size_t size_of_plaintext = (4*blocks_of_5) + 1;
	char *plaintext = new char[size_of_plaintext];
	char *un_armor = new char[size_of_plaintext];
	plaintext[size_of_plaintext-1] = '\0';
	un_armor[size_of_plaintext-1] = '\0';
	std::size_t u{0};
	int f=0;
	int u_limit = 0;
	int l_limit = 0;
	std::size_t sum=0;
	for(u=0; u<charlen ; u= u+5)
	{
		sum=0;
		u_limit = f+4;
		l_limit = f;
		ciphertext[u] = (ciphertext[u] - 33);
		ciphertext[u+1] = (ciphertext[u+1] - 33);
		ciphertext[u+2] = (ciphertext[u+2] - 33);
		ciphertext[u+3] = (ciphertext[u+3] - 33);
		ciphertext[u+4] = (ciphertext[u+4] - 33);
		sum = (ciphertext[u]*pow(85,4)) + (ciphertext[u+1]*pow(85,3) ) + (ciphertext[u+2]*pow(85,2)) + (ciphertext[u+3]*pow(85,1)) + (ciphertext[u+4]*pow(85,0)) ;
		while(u_limit-1>=l_limit)
		{

			un_armor[u_limit-1] = sum&(255);
			u_limit--;
			sum = sum>>8;
			f++;
		}
	}

	unsigned int k{0};
				unsigned int s[256];
				for(k=0; k<256 ; k++)
				{
					s[k]=k;
				}
				unsigned int i{0}, j{0};
				unsigned int tmp{0}, m=0;
				for(m=0; m<256 ; m++)
				{
					k = i%64;
					j = (j + s[i] + ((key>>k)&1L))%256;
					tmp = s[i];
					s[i]= s[j];
					s[j] = tmp;
					i= (i+1)%256;
				}


				unsigned int tmp1{0};
				p =0;
				unsigned int r{0} , R{0};

				while(p < size_of_plaintext-1)
				{
					i = (i+1)%256;
					j = (j + s[i])%256;
					tmp1  = s[i];
					s[i] = s[j];
					s[j] = tmp1;
					r = (s[i] + s[j])%256;
					R = s[r];
					plaintext[p] = R^(un_armor[p]);
					//std::cout << static_cast<int>(plaintext[p]) << " ";
					p++;
				}
		return plaintext;
	}
