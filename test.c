#include "./main.c"

int main(){

    /*
    // Alice computes original MAC
    unsigned char text[77] = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon";

    unsigned char hash1[16];
    MD4(hash1,text,77);

    
    //a = 0x67452301;
	//b = 0xefcdab89;
	//c = 0x98badcfe;
	//d = 0x10325476;
    
    unsigned char hash2[16];
    MD4WithStartingRegisters(hash2, text, 77, 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0);

    unsigned char hash3[16];
    unsigned char text2[20] = "THISISAPLAINTEXT!!!!";
    MD4(hash3, text2, 20);
    // Correct Little-Endian reconstruction
    uint32_t reg1 = (uint32_t)hash3[0] | ((uint32_t)hash3[1] << 8) | ((uint32_t)hash3[2] << 16) | ((uint32_t)hash3[3] << 24);
    uint32_t reg2 = (uint32_t)hash3[4] | ((uint32_t)hash3[5] << 8) | ((uint32_t)hash3[6] << 16) | ((uint32_t)hash3[7] << 24);
    uint32_t reg3 = (uint32_t)hash3[8] | ((uint32_t)hash3[9] << 8) | ((uint32_t)hash3[10] << 16) | ((uint32_t)hash3[11] << 24);
    uint32_t reg4 = (uint32_t)hash3[12] | ((uint32_t)hash3[13] << 8) | ((uint32_t)hash3[14] << 16) | ((uint32_t)hash3[15] << 24);

    int original_data_len = 20;
    // This calculates the next multiple of 64
    int totalBytesProcessed = ((original_data_len + 8) / 64 + 1) * 64;

    unsigned char hash4[16];
    MD4WithStartingRegisters(hash4,"",0,reg1,reg2,reg3,reg4,totalBytesProcessed);
    */
    // 1. Get the base hash
    unsigned char base_hash[16];
    unsigned char text[20] = "THISISAPLAINTEXT!!!!";
    MD4(base_hash, text, 20);

    // 2. Setup registers (Your Little-Endian code is now correct!)
    uint32_t reg1 = (uint32_t)base_hash[0] | ((uint32_t)base_hash[1] << 8) | ((uint32_t)base_hash[2] << 16) | ((uint32_t)base_hash[3] << 24);
    uint32_t reg2 = (uint32_t)base_hash[4] | ((uint32_t)base_hash[5] << 8) | ((uint32_t)base_hash[6] << 16) | ((uint32_t)base_hash[7] << 24);
    uint32_t reg3 = (uint32_t)base_hash[8] | ((uint32_t)base_hash[9] << 8) | ((uint32_t)base_hash[10] << 16) | ((uint32_t)base_hash[11] << 24);
    uint32_t reg4 = (uint32_t)base_hash[12] | ((uint32_t)base_hash[13] << 8) | ((uint32_t)base_hash[14] << 16) | ((uint32_t)base_hash[15] << 24);

    // 3. Compute extended hash
    // This simulates adding "HELLO" to the end of the original message + its padding
    unsigned char extended_hash[16];
    MD4WithStartingRegisters(extended_hash, "HELLO", 5, reg1, reg2, reg3, reg4, 64);

    // 4. Verification
    // To check if it worked, manually construct the full string Alice would have hashed:

    unsigned char* full = malloc(20+44+5);
    memcpy(full, text, 20);
    int gluePaddingLength = -1;
    unsigned char* gluePadding = getGluePadding(text,20,0,&gluePaddingLength);
    memcpy(full+20,gluePadding,gluePaddingLength);
    memcpy(full+20+gluePaddingLength,"HELLO",5);
    //unsigned char* full = [20 bytes text] + [44 bytes MD4 Padding] + ["HELLO"]
    unsigned char hashToCompare[16];
    MD4(hashToCompare,full,69); //should equal extended_hash
    return 0;
}