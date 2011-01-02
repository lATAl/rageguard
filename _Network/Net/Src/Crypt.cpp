#include "StdAfx.h"
#include "Crypt.h"

#define CY_CIPHERMAX 256

DWORD CEncrypt::m_dwCipher[CY_CIPHERMAX] =
{
	0x8B8624FB , 0x2AA8EAE3 , 0xE6AB92E1 , 0x800AAF82 , 
	0xEEFBB098 , 0xEE69BABA , 0x16B2EE28 , 0x3F6961B9 , 
	0x9DA62F6B , 0x1BE40D43 , 0xB813230A , 0xE094FD3D , 
	0xDF8F0EEE , 0xAF806231 , 0x3E1829EF , 0xEA02EE36 , 
	0x3D1EDE9A , 0xE1838DFA , 0x1232860F , 0xF83E688E , 
	0x2E3A09F0 , 0x6A86461E , 0xE0F03422 , 0x899A400A , 
	0x3A3E2A8F , 0x9ED1E8FE , 0xEDD83BEF , 0x0FE4F6BE , 
	0xD99DBAEE , 0x088E432F , 0xA182E18F , 0x0E32FE0A , 
	0x94D21931 , 0x3E8F8A29 , 0xE4F6B08A , 0xFF6BB063 , 
	0xE286FA68 , 0x98816A83 , 0xFF3E3F38 , 0x69D9B881 , 
	0x6E00BABF , 0xB2DB02A6 , 0x69ABDA91 , 0xE402938E , 
	0x68EAE8E8 , 0x0088A92A , 0xBAAE2FEE , 0xA88FA8EB , 
	0x80B4FBF8 , 0x1D8AEA6A , 0x4BDA9FA3 , 0x8EBA9088 , 
	0x4EDF6BEA , 0x8E691208 , 0xE394BF6E , 0xDD24EEB9 , 
	0x12E0DEFE , 0x8DE2D46B , 0x9A8B0880 , 0x2D6EB6F6 , 
	0x8E8EAEE0 , 0x916BA423 , 0x4913F19A , 0xEAD8F0E9 , 
	0x119382EE , 0x82AEFBB3 , 0x4AB81318 , 0xA21008B9 , 
	0x3A48A3A8 , 0xA9AD8094 , 0x2E09D49D , 0xD68E8E2D , 
	0x6EDD8886 , 0x8D064B4D , 0x81AAEEAE , 0x0EE4AEBE , 
	0x38E2F9E6 , 0xA69F3848 , 0x6E8A898E , 0xBB3FD1E4 , 
	0x289E4EAE , 0xAE9FA41B , 0xE8B11B9A , 0x8BA60FFA , 
	0xADEA1011 , 0x88AF2230 , 0x0A8E8EDA , 0xA8F1AFAE , 
	0x4FDAB6BD , 0x823A3A2E , 0xAEA11988 , 0x8038BAA3 , 
	0xA344D908 , 0x80EF4A6A , 0x18084812 , 0x14B34ADE , 
	0xE39ADF8A , 0x0EDEE381 , 0xEDE9B92A , 0x99F99E42 , 
	0xB64A33EA , 0xFDEE8AE8 , 0x8D1BBD28 , 0x98A4284D , 
	0xB4EE8A22 , 0xAEA8B819 , 0x8E88FA9A , 0x88BA9E44 , 
	0x46D24E48 , 0x8F0EF4AA , 0x83A6DAF3 , 0xF23432F1 , 
	0xF3BEE688 , 0x201BB6F3 , 0x88DEDEE6 , 0x6E89B2AA , 
	0x43E4FA80 , 0xFA398AAE , 0x98B8818E , 0x4103A8E8 , 
	0xAF02E2A3 , 0x8BE0DE22 , 0xF2AB6FBD , 0x2648F233 , 
	0xAEAD4A84 , 0x848633E6 , 0x2841EDE1 , 0xA8D1E113 , 
	0xE8DF819E , 0xDAA41F83 , 0xB80083A0 , 0xE8166B1F , 
	0xA69E3683 , 0x969208A1 , 0x2261EAF1 , 0x8EAF4A91 , 
	0x3F33D041 , 0x0F28A938 , 0xFEDE69FD , 0x49E4FE2F , 
	0x9B36D6EE , 0xADEDFA4F , 0x8DF988DE , 0x8EAEE682 , 
	0x121EE1B1 , 0x18EA0E2F , 0x8D3FD036 , 0xB2E0A981 , 
	0x2D881833 , 0xB9FA1F81 , 0x8418E8A2 , 0x8088AE86 , 
	0x83A183EE , 0x089EB98B , 0xAB2AE83A , 0x00AEAE3A , 
	0x1DFBFA44 , 0x9B3180B8 , 0x89EEB9E4 , 0x193490AE , 
	0xF28B86D3 , 0xEE8E8ED9 , 0xDA8EA209 , 0x348AAE11 , 
	0xAA19AE20 , 0x62AABB4D , 0x1BEB4B11 , 0xE81F9B28 , 
	0x0DEE8A98 , 0x961EAD9B , 0x9FA40E94 , 0x4D62944D , 
	0x24EDA3E8 , 0x1EB23E29 , 0x0B90AE09 , 0x4BF9EFFA , 
	0xA6B4D012 , 0x34EE8690 , 0xE8E818EA , 0x4B4BD4BD , 
	0x4BF9A92A , 0xA00AEB4A , 0x8AEE83BD , 0xB4E22E18 , 
	0x4E24FA8A , 0xE9ADEAD8 , 0x49DEB6FB , 0x2E343EA0 , 
	0xE0ADE148 , 0x1A80B2B9 , 0x11AFE92B , 0x02EA936E , 
	0xAF1BEF6D , 0x22AB2263 , 0x394B04EA , 0xEA2EE166 , 
	0xB1EA0931 , 0xA3A6A18E , 0x38B9E068 , 0x38B23204 , 
	0x0F99283E , 0xA149B622 , 0x8A41F46E , 0x8814AEAF , 
	0xF1A9B4E6 , 0xB4FEEA46 , 0xBDABB86A , 0x8EB9FBEF , 
	0x0D9F33E6 , 0xA4268434 , 0x32EE98E1 , 0x181A432E , 
	0xADE21F88 , 0xDA40FEA2 , 0x9FB3122B , 0x4EAFDE0E , 
	0x681BEF1B , 0xBDF22A99 , 0x8AE3EAFF , 0xA10032FE , 
	0xB6A21B80 , 0xD6A48AF1 , 0xEDA32DAA , 0x2FA8E96F , 
	0x201F3E2E , 0xBEDD1A21 , 0xD04EABD9 , 0xDE088AFF , 
	0x3DEAE986 , 0xEA0ADBB3 , 0x9AEBD9FD , 0xEAAA0E14 , 
	0x86AA3B0A , 0x9FB8230D , 0xB3812F8D , 0x010A9E46 , 
	0x01B90848 , 0x9DA989A8 , 0xA3992600 , 0x98BE8E0E , 
	0xE8BDEAAE , 0x88A2682E , 0xF3EB48FD , 0x291DF6DF , 
	0x430FF8E4 , 0x49DA80F0 , 0x2AEF28DD , 0x2AB1D33A , 
	0xD8460B01 , 0xF68BE18E , 0xA0FD1D28 , 0x1A20AABE , 
	0xE1DE8A0E , 0xE94B40AE , 0xFEBEB8A6 , 0x90E364B6 
};

//========================================================================
//CEncrypt
//========================================================================
CEncrypt::CEncrypt(void)
{

}

CEncrypt::~CEncrypt(void)
{

}

void CEncrypt::Encrypt( LPVOID pDestination , LPCVOID pSource , DWORD dwSize , DWORD dwCipher )
{
	/* Getting the Quotient and the Remainder of the data size */
	UINT nQuo = dwSize / 4; 
	UINT nRem = dwSize % 4;

	/* Casting the source data and the destination buffer as DWORD pointers */
	DWORD* pdwSource = (DWORD*)pSource;
	DWORD* pdwDestination = (DWORD*)pDestination;

	/* Casting the unique cipher(should vary for different functions) */
	LPBYTE pBYTE = (LPBYTE)&dwCipher;

	/* XORing the segments of the cipher together to create a pseudo-random index */
 	DWORD index = (DWORD)( pBYTE[0] ^ pBYTE[1] ^ pBYTE[2] ^ pBYTE[3] );

	/* XORing the main data */
	for( UINT i = 0 ; i < nQuo ; ++i )
	{
		/* XORing the source data with one of the 256 DWORDs above[using the modded the index(created using the original cipher provided)] */
		/* Then, XORing the data the with the original Cipher provided */
		pdwDestination[i] = pdwSource[i] ^ m_dwCipher[ ( i + index ) % CY_CIPHERMAX ] ^ dwCipher; 
	}

	/* XORing the remainder of the data using the same method */
	if( nRem == 1 )
	{
		( (LPBYTE)&pdwDestination[i] )[0] = ( (LPBYTE)&pdwSource[i] )[0] ^ ( (LPBYTE)&m_dwCipher[ ( i + index ) % CY_CIPHERMAX ] )[0];
	}
	else if( nRem == 2 )
	{
		( (LPBYTE)&pdwDestination[i] )[0] = ( (LPBYTE)&pdwSource[i] )[0] ^ ( (LPBYTE)&m_dwCipher[ ( i + index ) % CY_CIPHERMAX ] )[0];
		( (LPBYTE)&pdwDestination[i] )[1] = ( (LPBYTE)&pdwSource[i] )[1] ^ ( (LPBYTE)&m_dwCipher[ ( i + index ) % CY_CIPHERMAX ] )[1];
	}
	else if( nRem == 3 )
	{
		( (LPBYTE)&pdwDestination[i] )[0] = ( (LPBYTE)&pdwSource[i] )[0] ^ ( (LPBYTE)&m_dwCipher[ ( i + index ) % CY_CIPHERMAX ] )[0];
		( (LPBYTE)&pdwDestination[i] )[1] = ( (LPBYTE)&pdwSource[i] )[1] ^ ( (LPBYTE)&m_dwCipher[ ( i + index ) % CY_CIPHERMAX ] )[1];
		( (LPBYTE)&pdwDestination[i] )[2] = ( (LPBYTE)&pdwSource[i] )[2] ^ ( (LPBYTE)&m_dwCipher[ ( i + index ) % CY_CIPHERMAX ] )[2];
	}

}

DWORD* CEncrypt::GetCipher()
{
	return m_dwCipher;
}
