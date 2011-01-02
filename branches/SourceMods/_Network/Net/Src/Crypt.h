/*
----------------------------------------------------------------------
	filename: 	Encrypt.h
    created:	2011/1/02
	author:		[Xor-Net] Lethal
	
	purpose:	Base Packet Crypt Header

----------------------------------------------------------------------
*/
#ifndef __CRYPT_H__
#define __CRYPT_H__


#pragma once

#include <windows.h>



//========================================================================
//CEncrypt
//========================================================================
class CEncrypt
{
public:
	CEncrypt(void);
	virtual ~CEncrypt(void);
public:
	static void Encrypt( LPVOID pDestination , LPCVOID pSource , DWORD dwSize , DWORD dwCipher );
	
	static DWORD* GetCipher();

protected:

private:
	static DWORD m_dwCipher[];
};

#endif