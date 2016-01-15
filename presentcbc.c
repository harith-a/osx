#include "presentcbc.h"

uint8_t key[10] = "";
volatile uint8_t message[8] = "";


void decrypt(void)
{
	const uint8_t sBox4[] = {
							0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xf,0x8,0x4,0x7,0x1,0x2
							};

	const uint8_t invsBox4[] = {
							   0x5,0xe,0xf,0x8,0xc,0x1,0x2,0xd,0xb,0x4,0x6,0x3,0x0,0x7,0x9,0xa
							   };

//	Counter
	uint8_t i = 0;
//	pLayer variables
	uint8_t position = 0;
	uint8_t element_source = 0;
	uint8_t bit_source = 0;
	uint8_t element_destination = 0;
	uint8_t bit_destination = 0;
	uint8_t temp_pLayer[8];
//	Key scheduling variables
	uint8_t round = 0;
	uint8_t save1;
	uint8_t save2;
	uint8_t subkey[32][8];
//	****************** Encryption **************************
//	****************** Key Scheduling **********************
//	key precomputation
	for(i=2;i<=9;i++)
	{
		subkey[0][i-2] = key[i];
	}
	do
	{	
		i=0;
		save1  = key[0];
		save2  = key[1];	
		i = 0;
		do
		{
			key[i] = key[i+2];
			i++;
		}
		while(i<8);
		key[8] = save1;
		key[9] = save2;
		i = 0;
		save1 = key[0] & 7;
		do
		{
			key[i] = key[i] >> 3 | key[i+1] << 5;			
			i++;
		}
		while(i<9);
		key[9] = key[9] >> 3 | save1 << 5;

		key[9] = sBox4[key[9]>>4]<<4 | (key[9] & 0xF);

		if((round+1) % 2 == 1)
			key[1] ^= 128;
		key[2] = ((((round+1)>>1) ^ (key[2] & 15)) | (key[2] & 240));

		for(i=2;i<=9;i++)
		{
			subkey[round+1][i-2] = key[i];
		}

		round++;
	}
	while(round<31);
	
//	****************** End Key Scheduling ******************
	do	{
//	****************** addRoundkey *************************
		i=0;
		do
		{
			message[i] = message[i] ^ subkey[round][i];
			temp_pLayer[i] = 0;
			i++;
		}
		while(i<=7);
//	****************** End addRoundkey *********************
//	****************** pLayer ******************************
		for(i=0;i<64;i++)
		{
			position = (4*i) % 63;						//arthmetic calculation of the pLayer
			if(i == 63)									//Exception for bit 63
				position = 63;
			element_source = i / 8;
			bit_source = i % 8;
			element_destination = position / 8;
			bit_destination = position % 8;
			temp_pLayer[element_destination] |= ((message[element_source]>>bit_source) & 0x1) << bit_destination;
		}
		for(i=0;i<=7;i++)
		{
			message[i] = temp_pLayer[i];
		}
//	****************** End pLayer **************************
//	****************** sBox ********************************
		i=0;
		do
		{
			message[i] = invsBox4[message[i]>>4]<<4 | invsBox4[message[i] & 0xF];
			i++;
		}
		while(i<=7);
//	****************** End sBox ****************************
		round--;
	}
	while(round>0);
//	****************** addRoundkey *************************
	i = 0;
	do												//final key XOR
	{
		message[i] = message[i] ^ subkey[0][i];
		i++;
	}
	while(i<=7);


	// printf("\nDecrypted Message: ");
	// for ( i = 0 ; i < 8 ; i++ ) {
 //      printf( "%02X ", message[8 - 1 - i] );
 //    }
 //    printf( "\n" );	

	
//	****************** End addRoundkey *********************
//	****************** End Encryption **********************
}

void encryptt(void)
{
	const uint8_t sBox4[] =	{
							0xc,0x5,0x6,0xb,0x9,0x0,0xa,0xd,0x3,0xe,0xf,0x8,0x4,0x7,0x1,0x2
							};
//	Counter
	uint8_t i = 0;
//	pLayer variables
	uint8_t position = 0;
	uint8_t element_source = 0;
	uint8_t bit_source = 0;
	uint8_t element_destination	= 0;
	uint8_t bit_destination	= 0;
	uint8_t temp_pLayer[8];
//	Key scheduling variables
	uint8_t round;
	uint8_t save1;
	uint8_t save2;
//	****************** Encryption **************************
	round=0;
	do
	{
//	****************** addRoundkey *************************
		i=0;
		do
		{
			message[i] = message[i] ^ key[i+2];
			i++;
		}
		while(i<=7);
//	****************** sBox ********************************
		do
		{
			i--;
			message[i] = sBox4[message[i]>>4]<<4 | sBox4[message[i] & 0xF];
		}
		while(i>0);
//	****************** pLayer ******************************
		for(i=0;i<8;i++)
		{
			temp_pLayer[i] = 0;
		}
		for(i=0;i<64;i++)
		{
			position = (16*i) % 63;						//Artithmetic calculation of the pLayer
			if(i == 63)									//exception for bit 63
				position = 63;
			element_source		= i / 8;
			bit_source 			= i % 8;
			element_destination	= position / 8;
			bit_destination 	= position % 8;
			temp_pLayer[element_destination] |= ((message[element_source]>>bit_source) & 0x1) << bit_destination;
		}
		for(i=0;i<=7;i++)
		{
			message[i] = temp_pLayer[i];
		}
//	****************** End pLayer **************************
//	****************** Key Scheduling **********************
		save1  = key[0];
		save2  = key[1];	
		i = 0;
		do
		{
			key[i] = key[i+2];
			i++;
		}
		while(i<8);
		key[8] = save1;
		key[9] = save2;
		i = 0;
		save1 = key[0] & 7;								//61-bit left shift
		do
		{
			key[i] = key[i] >> 3 | key[i+1] << 5;			
			i++;
		}
		while(i<9);
		key[9] = key[9] >> 3 | save1 << 5;

		key[9] = sBox4[key[9]>>4]<<4 | (key[9] & 0xF);	//S-Box application

		if((round+1) % 2 == 1)							//round counter addition
			key[1] ^= 128;
		key[2] = ((((round+1)>>1) ^ (key[2] & 15)) | (key[2] & 240));
//	****************** End Key Scheduling ******************
		round++;
	}
	while(round<31);
//	****************** addRoundkey *************************
	i = 0;
	do										//final key XOR
	{
		message[i] = message[i] ^ key[i+2];
		i++;
	}
	while(i<=7);

	//Check Encrypted Message
	// printf("\nEncrypted Message: ");
	// for ( i = 0 ; i < 8 ; i++ ) {
 //      		printf( "%02X ", message[8 - 1 - i] );
 //    }
 //    printf( "\n" );	

//	****************** End addRoundkey *********************
//	****************** End Encryption  **********************
}



void encryptP(uint8_t *cipher, const uint8_t *plain, uint8_t *mykey)
{
    

    memcpy((void *)message,(const void *)plain,BLOCK_SIZE);
    memcpy((void *)key,(const void *)mykey,KEY_SIZE);
   	
   	encryptt();

   	memcpy(cipher,(const void *)message,BLOCK_SIZE);

}

void decryptP(uint8_t *plain, const uint8_t *cipher, uint8_t *mykey)
{
	memcpy((void *)message,(const void *)cipher,BLOCK_SIZE);
    memcpy((void *)key,(const void *)mykey,KEY_SIZE);
   	
   	decrypt();

   	memcpy((void *)plain,(const void *)message,BLOCK_SIZE);

}

void cbc_encrypt( uint8_t *key, const uint8_t *iv, uint8_t *data, size_t data_len)
{
        uint8_t cbc[BLOCK_SIZE];
        uint8_t *pos = data;
        int i, j, blocks;

        memcpy(cbc,iv,BLOCK_SIZE);

        blocks = data_len / BLOCK_SIZE;

        for (i = 0; i < blocks; i++) {
                for (j = 0; j < BLOCK_SIZE; j++)
                        cbc[j] ^= pos[j];	
                encryptP(cbc,cbc,key);
                memcpy(pos, cbc, BLOCK_SIZE);
                pos += BLOCK_SIZE;
        }
}

void cbc_decrypt( uint8_t *key, const uint8_t *iv, uint8_t *data, size_t data_len)
{
        uint8_t cbc[BLOCK_SIZE], tmp[BLOCK_SIZE];
        uint8_t *pos = data;
        int i, j, blocks;

        memcpy(cbc, iv, BLOCK_SIZE);

        blocks = data_len / BLOCK_SIZE;
        for (i = 0; i < blocks; i++) {
                memcpy(tmp, pos, BLOCK_SIZE);
                decryptP(pos, pos,key);
                for (j = 0; j < BLOCK_SIZE; j++)
                        pos[j] ^= cbc[j];
                memcpy(cbc, tmp, BLOCK_SIZE);
                pos += BLOCK_SIZE;
        }
}





