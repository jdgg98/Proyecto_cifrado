/*! 
 *  \file      aes_encrypt.hpp
 *  \brief     Este archivo contiene los métodos necesarios para realizar la encriptación de archivos con el esquema de cifrado AES.
 *  \details   En aes_encrypt.hpp están las funciones que definen los pasos necesarios para encriptar un archivo con el esquema de cifrado AES.
 *  \authors   Andres Corrales Vargas B72400
 *  \authors   Jafet Gutierrez Guevara B73558
 *  \version   1.0
 *  \date      10 de diciembre del 2019
 *  \bug       No hay bugs aquí
 *  \warning   El uso inapropiado de este programa provoca fallo general al mismo. Hacer caso a instrucciones.
 *  \copyright GNU Public License
 */
 
#include "aes_structures.hpp"

/*! \fn void AddRoundKey() 
 *  \brief Esta función realiza una suma XOR de un bloque de 128-bit con una llave de 128-bit. Sirve como la ronda inicial del cifrado.
 *  \return Esta función no tiene valor de retorno.
 */
void AddRoundKey(unsigned char* state, unsigned char* roundKey) 
{
	for (int i = 0; i < 16; i++) 
	{
		state[i] ^= roundKey[i];
	}
}

/*! \fn void SubBytes() 
 *  \brief Esta función realiza sustituciones en cada uno de los 16 bytes. Utiliza el S-box como tabla de búsqueda.
 *  \return Esta función no tiene valor de retorno.
 */
void SubBytes(unsigned char* state) 
{
	for (int i = 0; i < 16; i++) 
	{
		state[i] = s[state[i]];
	}
}

/*! \fn void ShiftRows() 
 *  \brief Esta función desplaza las filas a la izquierda.
 *  \return Esta función no tiene valor de retorno.
 */
void ShiftRows(unsigned char* state) 
{
	unsigned char tmp[16];

	/* Columna 1 */
	tmp[0] = state[0];
	tmp[1] = state[5];
	tmp[2] = state[10];
	tmp[3] = state[15];
	
	/* Columna 2 */
	tmp[4] = state[4];
	tmp[5] = state[9];
	tmp[6] = state[14];
	tmp[7] = state[3];

	/* Columna 3 */
	tmp[8] = state[8];
	tmp[9] = state[13];
	tmp[10] = state[2];
	tmp[11] = state[7];
	
	/* Columna 4 */
	tmp[12] = state[12];
	tmp[13] = state[1];
	tmp[14] = state[6];
	tmp[15] = state[11];

	for (int i = 0; i < 16; i++) 
	{
		state[i] = tmp[i];
	}
}

/*! \fn void MixColumns() 
 *  \brief Esta función utiliza las tablas de búsqueda de multiplicación de Galois (mul2, mul3) para alterar las columnas.
 *  \return Esta función no tiene valor de retorno.
 */
void MixColumns(unsigned char* state) 
{
	unsigned char tmp[16];

	tmp[0] = (unsigned char) mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3];
	tmp[1] = (unsigned char) state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3];
	tmp[2] = (unsigned char) state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]];
	tmp[3] = (unsigned char) mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]];

	tmp[4] = (unsigned char)mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7];
	tmp[5] = (unsigned char)state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7];
	tmp[6] = (unsigned char)state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]];
	tmp[7] = (unsigned char)mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]];

	tmp[8] = (unsigned char)mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11];
	tmp[9] = (unsigned char)state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11];
	tmp[10] = (unsigned char)state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]];
	tmp[11] = (unsigned char)mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]];

	tmp[12] = (unsigned char)mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^ state[15];
	tmp[13] = (unsigned char)state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^ state[15];
	tmp[14] = (unsigned char)state[12] ^ state[13] ^ mul2[state[14]] ^ mul3[state[15]];
	tmp[15] = (unsigned char)mul3[state[12]] ^ state[13] ^ state[14] ^ mul2[state[15]];

	for (int i = 0; i < 16; i++) 
	{
		state[i] = tmp[i];
	}
}

/*! \fn void Round() 
 *  \brief Esta función realiza los pasos para la encriptación. Cada round opera en 128 bits a la vez y el número de rounds se define en AESEncrypt().
 *  \return Esta función no tiene valor de retorno.
 */
void Round(unsigned char* state, unsigned char* key) 
{
	SubBytes(state);
	ShiftRows(state);
	MixColumns(state);
	AddRoundKey(state, key);
}

/*! \fn void FinalRound() 
 *  \brief Esta función ejecuta los mismos métodos que Round(), a excepción de MixColumns().
 *  \return Esta función no tiene valor de retorno.
 */
void FinalRound(unsigned char* state, unsigned char* key) 
{
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, key);
}

/*! \fn void AESEncrypt() 
 *  \brief Esta función ejecuta en orden todos los métodos necesarios para encriptar un texto.
 *  \return Esta función no tiene valor de retorno.
 */
void AESEncrypt(unsigned char* message, unsigned char* expandedKey, unsigned char* encryptedMessage) 
{
	unsigned char state[16];

	for (int i = 0; i < 16; i++) 
	{
		state[i] = message[i];
	}

	int numberOfRounds = 9;

	AddRoundKey(state, expandedKey);

	for (int i = 0; i < numberOfRounds; i++) 
	{
		Round(state, expandedKey + (16 * (i+1)));
	}

	FinalRound(state, expandedKey + 160);

	for (int i = 0; i < 16; i++) 
	{
		encryptedMessage[i] = state[i];
	}
}