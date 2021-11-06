/*! 
 *  \file      rsa.hpp
 *  \brief     Este es el archivo que contiene las funciones necesarias para el funcionamiento del algoritmo de cifrado y descifrado RSA.
 *  \details   En rsa.hpp está la clase con funciones matemáticas de RSA, algoritmos de cifrado y descifrado del mismo.
 *  \authors   Andres Corrales Vargas B72400
 *  \authors   Jafet Gutierrez Guevara B73558
 *  \version   1.0
 *  \date      10 de diciembre del 2019
 *  \bug       No hay bugs aquí
 *  \warning   El uso inapropiado de este programa provoca fallo general al mismo. Hacer caso a instrucciones.
 *  \copyright GNU Public License
 */

#include <chrono>
#include <random>
#include <cmath>
#include <string>
#include <cstdlib>
#include "aes_structures.hpp"

using namespace std;

int rsa_e, rsa_d, rsa_n;

/*! @arg rsa_e: Variable tipo int que guarda a la variable RSA e. */
/*! @arg rsa_d: Variable tipo int que guarda a la variable RSA d. */
/*! @arg rsa_n: Variable tipo int que guarda a la variable RSA n. */

/*! \fn int FastExponention(int bit, int n, int* y, int* a) 
*  \brief Esta función es la función matemática de exponenciación rápida para cifrado o descifrado y simplificación de exponenciación.
*  \return Esta función no tiene valor entero de retorno.
*/
void FastExponention(int bit, int n, int* y, int* a)
{
	if (bit == 1)
    {
        *y = (*y * (*a)) % n;
    }
	
	*a = (*a) * (*a) % n;
}

/*! \fn void FindT(int a, int m, int n) 
*  \brief Esta función es la función matemática para cifrar o descifrar un solo dato a partir de la llave publica o privada generada.
*  \return Esta función retorna el valor del dato cifrado o descifrado en forma de entero.
*/
int FindT(int a, int m, int n)
{
	int r;
	int y = 1;

	while (m > 0) {
		r = m % 2;
		FastExponention(r, n, &y, &a);
		m = m / 2;
	}
	return y;
}

/*! \fn int GreatestCommonDivisor(int a, int b)
*  \brief Esta función es la función matemática del máximo común divisor necesaria para generar llaves pública y privadas.
*  \return Esta función retorna el máximo común divisor que debería dar 1.
*/
int GreatestCommonDivisor(int a, int b)
{
    int t;
    while(1) 
    {
        t= a%b;
        if(t==0)
        {
            return b;
        }
        a = b;
        b= t;
    }
}

/*! \fn int PrimarityTest(int a, int i)
*  \brief Esta función es la función matemática para verificar si el número aleatorio generado para las llaves es primo.
*  \return Esta función retorna 1 si es primo y 0 si no lo es.
*/
int PrimarityTest(int a, int i)
{
	int n = i - 1;
	int k = 0;
	int j, m, T;

	while (n % 2 == 0)
    {
		k++;
		n = n / 2;
	}

	m = n;
	T = FindT(a, m, i);

	if (T == 1 || T == i - 1){return 1;}

	for (j = 0; j < k; j++) 
    {
		T = FindT(T, 2, i);
		if (T == 1){return 0;}
		else if (T == i - 1){return 1;}
	}
	return 0;
}

/*! \fn int MultiplicativeInverse(int a, int b)
*  \brief Esta función es la función matemática para obtener el inverso multiplicativo de un número, función necesaria para obtener parte de la clave privada.
*  \return Esta función retorna 1 si es primo y 0 si no lo es.
*/
int MultiplicativeInverse(int a, int b)
{
	int inv;
	int q, r, r1 = a, r2 = b, t, t1 = 0, t2 = 1;

	while (r2 > 0) 
    {
		q = r1 / r2;
		r = r1 - q * r2;
		r1 = r2;
		r2 = r;
		t = t1 - q * t2;
		t1 = t2;
		t2 = t;
	}

	if (r1 == 1){inv = t1;}
	if (inv < 0){inv = inv + a;}

	return inv;
}

/*! \fn void RSAKeyGeneration()
*  \brief Esta función es la función principal encargada de generar las llaves públicas y privadas.
*  \return Esta función no tiene valor de retorno.
*/
void RSAKeyGeneration()
{
	int p, q;
	
	unsigned seed = chrono::steady_clock::now().time_since_epoch().count();
	default_random_engine generator(seed);
	uniform_int_distribution<int> dist_pq(2, 200);
	
	do {
		do
			p = dist_pq(generator);
		while (p % 2 == 0);

	} while (!PrimarityTest(2, p));

	do {
		do
        {
            q = dist_pq(generator);
        }
		while (q % 2 == 0);
	} while (!PrimarityTest(2, q));

	rsa_n = p * q;

	int phi = (p - 1) * (q - 1);
	uniform_int_distribution<int> dist_e(2, phi);

	do
    {
        rsa_e = dist_e(generator); // 1 < e < phi_n
    }
	while (GreatestCommonDivisor(rsa_e, phi) != 1);

	rsa_d = MultiplicativeInverse(phi, rsa_e);
}


/*! \fn void Encryption(int value, ofstream& out)
*  \brief Esta función es la función principal encargada de encriptar un entero.
*  \return Esta función no tiene valor de retorno.
*/
void Encryption(int value, ofstream& output_file)
{
	int cipher = FindT(value, rsa_e, rsa_n);
	output_file << cipher << " ";
}

/*! \fn void Decryption(int value, ofstream& out)
*  \brief Esta función es la función principal encargada de desencriptar un entero.
*  \return Esta función no tiene valor de retorno.
*/
void Decryption(int value, ofstream& output_file)
{
	int decipher = FindT(value, rsa_d, rsa_n);
	char ch = char(decipher);
	output_file.put(ch);
}

