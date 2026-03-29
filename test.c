#include "./main.c"

int main(){

    // Alice computes original MAC
    unsigned char text[77] = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

    unsigned char hash1[16];
    MD4(hash1,text,77);

    /*
    a = 0x67452301;
	b = 0xefcdab89;
	c = 0x98badcfe;
	d = 0x10325476;
    */
    unsigned char hash2[16];
    MD4WithStartingRegisters(hash2, text, 77, 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0);
    return 0;
}