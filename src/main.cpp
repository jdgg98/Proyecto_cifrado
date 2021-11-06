/*! 
 *  \brief     Este programa posee una interfaz básica de consola donde el usuario puede escribir el archivo a cifrar o descifrar archivos .txt a partir de los algoritmos AES y RSA 
 *  \authors   Andres Corrales Vargas B72400
 *  \authors   Jafet Gutierrez Guevara B73558
 *  \version   1.0
 *  \date      10 de diciembre del 2019
 *  \warning   El uso inapropiado de este programa provoca fallo general al mismo. Hacer caso a instrucciones.
 *  \copyright GNU Public License
 */

/*! \mainpage Pagina Principal del Proyecto 1: Comparación Espacio-Temporal de Algoritmos o Estructuras de Datos.
 *
 * \section :: Descripcion del programa
 *
 * Este programa es un programa capaz de cifrar o descifrar archivos .txt a partir de los algoritmos AES y RSA
 */


#include "aes_decrypt.hpp"
#include "rsa.hpp"

/*!
 *  \file      main.cpp
 *  \brief     Este es el archivo que contiene el programa principal, donde se ejecutan las instrucciones para correr los subprogramas AES y RSA para encriptado y desencriptado de archivos
 *  \details   En main.cpp se encuentra la función main donde se ejecutan todas los métodos, se inicializan y crean los objetos necesarios para el funcionamiento del programa.
 *  \authors   Andres Corrales Vargas B72400
 *  \authors   Jafet Gutierrez Guevara B73558
 *  \version   1.0
 *  \date      10 de diciembre del 2019
 *  \bug       No hay bugs aquí
 *  \warning   El uso inapropiado de este programa provoca fallo general al mismo. Hacer caso a instrucciones.
 *  \copyright GNU Public License supongo.
 */

/*! \fn int main() 
*  \brief La función main ejecuta los algoritmos AES y RSA
*  \return Esta funcion devuelve 0, siempre que su ejecución haya sido normal y sin errores.
*/

int main()
{
    char algorith_option; /*! @arg algorith_option: Atributo tipo char que guarda la opción de algoritmo a emplear para que el programa sepa cual algoritmo de cifrado de datos desea usar el usuario.*/

    system("clear");
    cout << "================================================================================" << endl;
    cout << " PROGRAMA DE ALGORITMOS DE CIFRADO Y DESCIFRADO AES Y RSA CREADO POR EL GRUPO 1" << endl;
    cout << "================================================================================" << endl << endl;
    cout << "Opciones: " << endl << endl << "a) Algoritmo AES" << endl << "r) Algoritmo RSA" << endl << endl << "Digite una opción: ";
    cin >> algorith_option;
    system("clear");

    if (algorith_option == 'a' || algorith_option == 'A')
    {
        char option = ' '; /*! @arg option: Atributo tipo char que guarda la opción de algoritmo AES a emplear para que el programa sepa si desea cifrar o descifrar archivo.*/
        char s; /*! @arg s: Atributo tipo char para que el usuario digite cualquier cosa para salir de una subopción.*/
        
        while(option != 's')
        {
            system("clear");
            cout << "============================================" << endl;
            cout << " Subprograma de AES de 128-bit" << endl;
            cout << "============================================" << endl << endl;
            cout << "Seleccione una opción: " << endl << "e) Encriptar archivo .txt" << endl << "d) Desencriptar archivo .txt" << endl << "s) Salir" << endl << endl;
            cin >> option;
            
            if(option == 'e')
            {
                system("clear");
                char message[100000]; /*! @arg s: Atributo tipo char[] donde se almacena una línea entera de texto leído del archivo original.*/
                string f; /*! @arg f: Atributo tipo string donde se almacena un caracter a la vez del archivo a encriptar.*/
                string file = "./"; /*! @arg f: Atributo tipo string donde se almacena el nombre del archivo a encriptar.*/
                string t; /*! @arg s: Atributo tipo string donde se almacena una línea entera de texto leído del archivo original.*/
                
                cout << "Digite el nombre del archivo que desea encriptar: ";
                cin >> f;
        
                file += f;
                ifstream fe(file); /*! @arg s: Atributo tipo ifstream donde se almacena una línea entera de texto leído del archivo original.*/
        
                while (!fe.eof())
                {
                    getline(fe, t);
                }
                fe.close();
        
                for(int i = 0; i < t.size(); i++)
                {
                    message[i] = t[i];
                }
        
                cout << endl << "Texto a encriptar: ";
                cout << message << endl << endl;


                // Pad message to 16 bytes
                int originalLen = strlen((const char*)message);

                int paddedMessageLen = originalLen;

                if ((paddedMessageLen % 16) != 0) 
                {
                    paddedMessageLen = (paddedMessageLen / 16 + 1) * 16;
                }

                unsigned char* paddedMessage = new unsigned char[paddedMessageLen];
                for (int i = 0; i < paddedMessageLen; i++) 
                {
                    if (i >= originalLen)
                    {
                        paddedMessage[i] = 0;
                    }
                    else 
                    {
                        paddedMessage[i] = message[i];
                    }
                }

                unsigned char * encryptedMessage = new unsigned char[paddedMessageLen]; 

                string str;
                ifstream infile;
                infile.open("keyfile");

                if (infile.is_open())
                {
                    getline(infile, str); // The first line of file should be the key
                    infile.close();
                }

                else cout << "El archivo no se pudo abrir" << endl << endl;

                istringstream hex_chars_stream(str);
                unsigned char key[16];
                int i = 0;
                unsigned int c;
                while (hex_chars_stream >> hex >> c)
                {
                    key[i] = c;
                    i++;
                }

                unsigned char expandedKey[176];
            
                //Aquí comienza la implemantación del AES para encriptar
                auto start = chrono::steady_clock::now();
                KeyExpansion(key, expandedKey);
                auto end = chrono::steady_clock::now();
                double elapsed_time = double(chrono::duration_cast<chrono::nanoseconds>(end-start).count());
                cout << "Tiempo de generación de las llaves: " << elapsed_time << " ns" << endl << endl;
                
                //Aquí comienza la implemantación del AES para encriptar
                start = chrono::steady_clock::now();

                for (int i = 0; i < paddedMessageLen; i += 16) 
                {
                    AESEncrypt(paddedMessage+i, expandedKey, encryptedMessage+i);
                }
                
                end = chrono::steady_clock::now();
                elapsed_time = double(chrono::duration_cast<chrono::nanoseconds>(end-start).count());
                cout << "Tiempo de encriptación: " << elapsed_time << " ns" << endl << endl;

                cout << "Contenido encriptado en hexadecimal:" << endl;
                for (int i = 0; i < paddedMessageLen; i++) 
                {
                    cout << hex << (int) encryptedMessage[i];
                    cout << " ";
                }

                cout << endl << endl;

                // Write the encrypted string out to file "message.aes"
                ofstream outfile;
                outfile.open("aes_encrypted.txt");
                if (outfile.is_open())
                {
                    outfile << encryptedMessage;
                    outfile.close();
                    cout << "El contenido encriptado se guardó en el archivo aes_encrypted.txt" << endl << endl << endl;
                }

                else cout << "El archivo no se pudo abrir" << endl << endl;

                // Free memory
                delete[] paddedMessage;
                delete[] encryptedMessage;
                
                cout << "Digite cualquier cosa para continuar: ";
                cin >> s;
            }
            
            else if(option == 'd')
            {
                system("clear");
                string f;
                
                cout << "Digite el nombre del archivo que desea desencriptar: ";
                cin >> f;
                
                string msgstr;
                ifstream infile;
                infile.open(f, ios::in | ios::binary);

                if (infile.is_open())
                {
                    getline(infile, msgstr); // The first line of file is the message
                    infile.close();
                    cout << endl << "Texto a desencriptar: " << msgstr << endl << endl;
                }

                else cout << "No se pudo abrir archivo" << endl << endl;

                char * msg = new char[msgstr.size()+1];

                strcpy(msg, msgstr.c_str());

                int n = strlen((const char*)msg);

                unsigned char * encryptedMessage = new unsigned char[n];
                for (int i = 0; i < n; i++) {
                    encryptedMessage[i] = (unsigned char)msg[i];
                }

                // Free memory
                delete[] msg;

                // Read in the key
                string keystr;
                ifstream keyfile;
                keyfile.open("keyfile", ios::in | ios::binary);

                if (keyfile.is_open())
                {
                    getline(keyfile, keystr); // The first line of file should be the key
                    keyfile.close();
                }

                else cout << "No se pudo abrir archivo";

                istringstream hex_chars_stream(keystr);
                unsigned char key[16];
                int i = 0;
                unsigned int c;
                while (hex_chars_stream >> hex >> c)
                {
                    key[i] = c;
                    i++;
                }

                unsigned char expandedKey[176];

                //Aquí comienza la implemantación del AES para desencriptar
                auto start = chrono::steady_clock::now();
                
                KeyExpansion(key, expandedKey);
                
                int messageLen = strlen((const char *)encryptedMessage);

                unsigned char * decryptedMessage = new unsigned char[messageLen];

                for (int i = 0; i < messageLen; i += 16) {
                    AESDecrypt(encryptedMessage + i, expandedKey, decryptedMessage + i);
                }
                
                auto end = chrono::steady_clock::now();
                double elapsed_time = double(chrono::duration_cast<chrono::nanoseconds>(end-start).count());
                
                cout << "Tiempo de desencriptación: " << elapsed_time << " ns" << endl << endl;

                cout << endl << "Contenido desencriptado en hexadecimal:" << endl;
                for (int i = 0; i < messageLen; i++) {
                    cout << hex << (int)decryptedMessage[i];
                    cout << " ";
                }
                cout << endl << endl;
                cout <<"Contenido desencriptado: ";
                for (int i = 0; i < messageLen; i++) {
                    cout << decryptedMessage[i];
                }
                
                cout << endl << endl;
                
                ofstream outfile;
                outfile.open("aes_decrypted.txt");
                if (outfile.is_open())
                {
                    outfile << decryptedMessage;
                    outfile.close();
                    cout << "El contenido desencriptado se guardó en el archivo aes_decrypted.txt" << endl << endl << endl;
                }

                else cout << "No se pudo abrir archivo";
                
                cout << "Digite cualquier cosa para continuar ";
                cin >> s;
            }
        }
        system("clear");
    }
    /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
    else if (algorith_option == 'r' || algorith_option == 'R')
    {
        ifstream input_file; /*! @arg input_file: Atributo tipo ifstream donde se almacenan los archivos a leer.*/
        ofstream output_file; /*! @arg output_file: Atributo tipo ifstream donde se almacenan los archivos a escribir.*/
        string input_name; /*! @arg input_name: Atributo tipo string donde se guarda el nombre de los archivos a leer.*/
        string output_name; /*! @arg output_name: Atributo tipo string donde se guarda el nombre de los archivos a escribir.*/

        int rsa_char_counter; /*! @arg rsa_char_counter: Atributo tipo int donde se guarda los caracteres leidos del archivo a cifrar.*/
        char option = 'n', sub_option;

        /*! @arg option: Atributo tipo char donde se guarda la opción a elegir del usuario.*/
        /*! @arg sub_option: Atributo tipo char para digitar cualquier cosa para salir.*/

        while (option != 's' || option != 'S')
        {
            system("clear");
            cout << "====================" << endl;
            cout << " Subprograma de RSA" << endl;
            cout << "====================" << endl;
            cout << "Estas son las opciones: " << endl << endl << "e) Encriptar archivo .txt" << endl << "d) Desencriptar archivo .txt" 
            << endl << "s) Salir del programa (si pierde las claves no podrá desencriptar el archivo)" << endl << endl << "Digite la opcion: ";
            cin >> option;
            system("clear");

            if (option == 'e' || option == 'E')
            {
                rsa_char_counter = 0;
                RSAKeyGeneration();
                cout << "Encriptación de archivo" << endl << endl;
                cout << "Digite el nombre del archivo a cifrar de la forma (texto.txt): "; cin >> input_name;

                input_file.open(input_name);

                if (input_file.fail()) 
                {
                    cout << "Error al abrir archivo a leer o archivo a leer no encontrado." << endl;
                    return 1;
                }

                output_file.open("cifrado.txt");

                if (output_file.fail())
                {
                    cout << "Error al crear archivo de cifrado." << endl;
                    return 1;
                }

                ///midiendo tiempos aqui
                auto start = chrono::steady_clock::now(); /*! @arg start: Atributo tipo auto para almacenar el tiempo inicial del algoritmo de cifrado RSA.*/
                //////

                while (1)
                {
                    char ch;
                    input_file.get(ch);

                    if (input_file.eof())
                    {
                        break;
                    }

                    int value = int(ch);
                    Encryption(value, output_file);
                    rsa_char_counter++;
                }

                ///midiendo tiempos aqui
                auto end = chrono::steady_clock::now(); /*! @arg end: Atributo tipo auto para almacenar el tiempo final del algoritmo de cifrado RSA.*/
                double elapsed_time = double(chrono::duration_cast<chrono::microseconds>(end-start).count()); /*! @arg elapsed_time: Atributo tipo double para almacenar el tiempo total en números del algoritmo de cifrado RSA.*/
                //////

                input_file.close();
                output_file.close();

                cout << endl << "Estas son las claves generadas. Recuerde que sin la clave privada NO PODRÁ DESENCRIPTAR EL ARCHIVO." << endl << endl;
                cout << "Clave pública: " << rsa_e << " " << rsa_n << " " << rsa_char_counter << endl;
                cout << "Clave privada: " << rsa_d << " " << rsa_n << " " << rsa_char_counter << endl << endl;
                cout <<"AVISO: Archivo de cifrado (cifrado.txt) creado correctamente en " << elapsed_time << " microsegundos\a" << endl;
                cout << "Digite lo que sea para continuar: ";
                cin >> sub_option;
            }

            else if (option == 'd' || option == 'D')
            {
                cout << "Desencriptación de archivos" << endl << endl;
                cout << "Digite la clave privada que se generó cuando encriptó el archivo. (Si no la tiene no puede desencriptarlo)" << endl;
                cout << "Esta clave era una clave de tres números. Escriba esos números separados por espacio: " << endl << endl;
                cin >> rsa_d; cin >> rsa_n; cin >> rsa_char_counter;
                cout << endl;
                
                input_file.open("cifrado.txt");

                if (input_file.fail())
                {
                    cout << "Error abriendo archivo (cifrado.txt) con información cifrada." << endl;
                    return 1;
                }

                output_file.open("descifrado.txt");

                if (output_file.fail())
                {
                    cout << "Error abriendo archivo a guardar la información descifrada." << endl;
                    return 1;
                }

                ///midiendo tiempos aqui
                auto start = chrono::steady_clock::now(); /*! @arg start: Atributo tipo auto para almacenar el tiempo inicial del algoritmo de descifrado RSA.*/
                //////

                for (int i = 0; i < rsa_char_counter; i++)
                {
                    int cip;
                    input_file >> cip;
                    Decryption(cip, output_file);
                }

                ///midiendo tiempos aqui
                auto end = chrono::steady_clock::now(); /*! @arg end: Atributo tipo auto para almacenar el tiempo final del algoritmo de descifrado RSA.*/
                double elapsed_time = double(chrono::duration_cast<chrono::microseconds>(end-start).count()); /*! @arg elapsed_time: Atributo tipo double para almacenar el tiempo total en números del algoritmo de descifrado RSA.*/
                //////
                
                input_file.close();
                output_file.close();
                cout << "AVISO: Archivo de descifrado (descifrado.txt) creado correctamente en " << elapsed_time << " microsegundos\a" << endl;
                cout << "Digite lo que sea para continuar: ";
                cin >> sub_option;
            }

            else if (option == 's' || option == 'S')
            {
                return 0;
            }
        }

        system("clear");
    }

    else {cout << "Intente de nuevo digitando una opción válida";}
    return 0;
}

