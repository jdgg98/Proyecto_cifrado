/*! 
 *  \file      aes_decrypt.hpp
 *  \brief     Este archivo contiene los métodos necesarios para realizar la desencriptación de archivos cifrados con el algoritmo AES.
 *  \details   En aes_decrypt.hpp están las funciones que definen los pasos necesarios para desencriptar un archivo cifrado con el algoritmo AES.
 *  \authors   Andres Corrales Vargas B72400
 *  \authors   Jafet Gutierrez Guevara B73558
 *  \version   1.0
 *  \date      10 de diciembre del 2019
 *  \bug       No hay bugs aquí
 *  \warning   El uso inapropiado de este programa provoca fallo general al mismo. Hacer caso a instrucciones.
 *  \copyright GNU Public License
 */

#include "aes_encrypt.hpp"

/*! \fn void InverseSubRoundKey() 
 *  \brief Esta función realiza una suma XOR de un bloque de 128-bit con una llave de 128-bit.
 *  \return Esta función no tiene valor de retorno.
 */
void InverseSubRoundKey(unsigned char* state, unsigned char* roundKey) 
{
	for (int i = 0; i < 16; i++) 
	{
		state[i] ^= roundKey[i];
	}
}

/*! \fn void InverseMixColumns() 
 *  \brief Esta función utiliza las tablas de búsqueda de multiplicación de Galois (mul9, mul11, mul13, mul14), para revertir el efecto del método MixColumns ejecutado en la encriptación.
 *  \return Esta función no tiene valor de retorno.
 */
void InverseMixColumns(unsigned char* state) 
{
	unsigned char tmp[16];

	tmp[0] = (unsigned char)mul14[state[0]] ^ mul11[state[1]] ^ mul13[state[2]] ^ mul9[state[3]];
	tmp[1] = (unsigned char)mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^ mul13[state[3]];
	tmp[2] = (unsigned char)mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^ mul11[state[3]];
	tmp[3] = (unsigned char)mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^ mul14[state[3]];

	tmp[4] = (unsigned char)mul14[state[4]] ^ mul11[state[5]] ^ mul13[state[6]] ^ mul9[state[7]];
	tmp[5] = (unsigned char)mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^ mul13[state[7]];
	tmp[6] = (unsigned char)mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^ mul11[state[7]];
	tmp[7] = (unsigned char)mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^ mul14[state[7]];

	tmp[8] = (unsigned char)mul14[state[8]] ^ mul11[state[9]] ^ mul13[state[10]] ^ mul9[state[11]];
	tmp[9] = (unsigned char)mul9[state[8]] ^ mul14[state[9]] ^ mul11[state[10]] ^ mul13[state[11]];
	tmp[10] = (unsigned char)mul13[state[8]] ^ mul9[state[9]] ^ mul14[state[10]] ^ mul11[state[11]];
	tmp[11] = (unsigned char)mul11[state[8]] ^ mul13[state[9]] ^ mul9[state[10]] ^ mul14[state[11]];

	tmp[12] = (unsigned char)mul14[state[12]] ^ mul11[state[13]] ^ mul13[state[14]] ^ mul9[state[15]];
	tmp[13] = (unsigned char)mul9[state[12]] ^ mul14[state[13]] ^ mul11[state[14]] ^ mul13[state[15]];
	tmp[14] = (unsigned char)mul13[state[12]] ^ mul9[state[13]] ^ mul14[state[14]] ^ mul11[state[15]];
	tmp[15] = (unsigned char)mul11[state[12]] ^ mul13[state[13]] ^ mul9[state[14]] ^ mul14[state[15]];

	for (int i = 0; i < 16; i++) 
	{
		state[i] = tmp[i];
	}
}

/*! \fn void InverseShiftRows() 
 *  \brief Esta función desplaza las filas a la derecha (en lugar de a la izquierda) para descifrar
 *  \return Esta función no tiene valor de retorno.
 */
void InverseShiftRows(unsigned char* state) 
{
	unsigned char tmp[16];

	/* Columna 1 */
	tmp[0] = state[0];
	tmp[1] = state[13];
	tmp[2] = state[10];
	tmp[3] = state[7];

	/* Columna 2 */
	tmp[4] = state[4];
	tmp[5] = state[1];
	tmp[6] = state[14];
	tmp[7] = state[11];

	/* Columna 3 */
	tmp[8] = state[8];
	tmp[9] = state[5];
	tmp[10] = state[2];
	tmp[11] = state[15];

	/* Columna 4 */
	tmp[12] = state[12];
	tmp[13] = state[9];
	tmp[14] = state[6];
	tmp[15] = state[3];

	for (int i = 0; i < 16; i++) 
	{
		state[i] = tmp[i];
	}
}

/*! \fn void InverseSubBytes() 
 *  \brief Esta función realiza una sustitución a cada uno de los 16 bytes. Utiliza el S-box como tabla de búsqueda.
 *  \return Esta función no tiene valor de retorno.
 */
void InverseSubBytes(unsigned char* state) 
{
	for (int i = 0; i < 16; i++) 
	{
		state[i] = inv_s[state[i]];
	}
}

/*! \fn void InverseRound() 
 *  \brief Esta función realiza el reverso de los pasos para encriptación. Cada round opera en 128 bits a la vez y el número de rounds se define en AESDecrypt().
 *  \return Esta función no tiene valor de retorno.
 */
void InverseRound(unsigned char* state, unsigned char* key) 
{
	InverseSubRoundKey(state, key);
	InverseMixColumns(state);
	InverseShiftRows(state);
	InverseSubBytes(state);
}

/*! \fn void InverseInitialRound() 
 *  \brief Esta función ejecuta los mismos métodos que InverseRound(), a excepción de InverseMixColumns().
 *  \return Esta función no tiene valor de retorno.
 */
void InverseInitialRound(unsigned char* state, unsigned char* key)
{
	InverseSubRoundKey(state, key);
	InverseShiftRows(state);
	InverseSubBytes(state);
}

/*! \fn void AESDecrypt() 
 *  \brief Esta función ejecuta en orden todos los métodos necesarios para desencriptar un texto.
 *  \return Esta función no tiene valor de retorno.
 */
void AESDecrypt(unsigned char* encryptedMessage, unsigned char* expandedKey, unsigned char* decryptedMessage)
{
	unsigned char state[16];

	for (int i = 0; i < 16; i++) 
	{
		state[i] = encryptedMessage[i];
	}

	InverseInitialRound(state, expandedKey+160);

	int numberOfRounds = 9;

	for (int i = 8; i >= 0; i--) 
	{
		InverseRound(state, expandedKey + (16 * (i + 1)));
	}

	InverseSubRoundKey(state, expandedKey);

	for (int i = 0; i < 16; i++) 
	{
		decryptedMessage[i] = state[i];
	}
}