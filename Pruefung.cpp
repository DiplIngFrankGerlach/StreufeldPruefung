/* Testcode zur Bewertung verschiedener Hashfunktionen 
    
   Autor: Frank Gerlach, frankgerlach.tai@gmx.de

   Kommentare, Konstruktive Kritik und Anregungen sind willkommen !

*/

#include <iostream>
#include <stdint.h>
#include <assert.h>
#include <stdlib.h>
#include <memory.h>
#include <stdio.h>
#include "suchoi.h"
#include "Adler32.h"
#include <vector>
#include "sha256.h"



using namespace std;


void sichere(bool bedingung,const char* text)
{
    if( bedingung == false)
    {
       cerr << "fehlgeschlagen: " << text  << endl;
       exit(-1);
    }
}



uint32_t sha256_streusumme(const void* eingabe,size_t groesse)
{
   SHA256_CTX sc;
   sha256_init(&sc);
   sha256_update(&sc,(const BYTE*)eingabe,groesse);
   BYTE streusumme[32];
   sha256_final(&sc,streusumme);
   uint32_t ergebnis(0);
   for(uint8_t i=0; i < 8; i++)
   {
     uint32_t* zeiger = (uint32_t*)&(streusumme[i*4]);
     ergebnis ^= (*zeiger);
   }
   return ergebnis;
}

//uint32_t nZahlen = 999983;//Primzahl nahe 1 Million
//uint32_t nZahlen = 1000000;
uint32_t nZahlen;

void setzeNull(vector<uint32_t>& v)
{
   for(uint32_t i=0; i < v.size(); i++)
   {
     v.at(i) = 0;
   }
}

 
void druckeHistogramm(vector<uint32_t>& zaehlerFeld, uint32_t maxHaeufigkeit)
{
   vector<uint32_t> histogramm;
   histogramm.resize(maxHaeufigkeit+1);

   setzeNull(histogramm);

   for(uint64_t i=0; i < zaehlerFeld.size(); i++)
   {
      uint32_t anz = zaehlerFeld.at(i);
      if( anz >= maxHaeufigkeit )
      {
          histogramm.at(maxHaeufigkeit)++;
      }
      else
      {
         histogramm.at(anz)++;
      } 
   }
   uint32_t summe(0);
   for(uint32_t i=0; (i < maxHaeufigkeit) && (summe < nZahlen); i++)
   {
       summe += histogramm.at(i);
       cout << i << " " << histogramm.at(i) << endl;
   }
   sichere(summe <= nZahlen, "Summe in druckeHistogramm");
   if( histogramm.at(maxHaeufigkeit) > 0 )
   {
      cout << "mehr als " << maxHaeufigkeit << " " << histogramm.at(maxHaeufigkeit) << endl;
   }
}



void PruefungZahlen( uint32_t (*StreuFunktion)(const void*,size_t groesse) )
{
    
   vector<uint32_t> zaehlerFeld;
   zaehlerFeld.resize(nZahlen);
   setzeNull(zaehlerFeld);
   for(uint32_t i=0; i < nZahlen; i++)
   {
      uint32_t stelle = StreuFunktion(&i,sizeof(uint32_t)) % nZahlen;
      zaehlerFeld.at(stelle )++;
   }
   druckeHistogramm(zaehlerFeld,200);
}

/*Pruefalgorithmus mit Zahlen im Abstand von 100 */
void PruefungZahlenAbstand( uint32_t (*StreuFunktion)(const void*,size_t groesse) )
{
   cout << "Pruefung Zahlen mit Abstand 100" << endl; 
   vector<uint32_t> zaehlerFeld;
   zaehlerFeld.resize(nZahlen);

   setzeNull(zaehlerFeld);

   for(uint32_t i=0; i < nZahlen; i++)
   {
      uint32_t pruefZahl = i * 100;
      uint32_t stelle = StreuFunktion(&pruefZahl,sizeof(uint32_t)) % nZahlen;
      zaehlerFeld.at(stelle)++;
   }
   druckeHistogramm(zaehlerFeld,200);
}

/* Pruefe Streufunktionen mittels Zeichenketten der Laenge 10..168 Zeichen */
void PruefungZeichenketten(uint32_t (*StreuFunktion)(const void*,size_t groesse) )
{
    
   char puffer[30];
   strcpy(puffer,"AntonBmann"); 
   vector<uint32_t> zaehlerFeld;
   zaehlerFeld.resize(nZahlen);

   setzeNull(zaehlerFeld);

   for(uint32_t i=0; i < nZahlen; i++)
   {
      uint32_t dazu = i*1017/11;
      char puffer2[11];
      puffer[10] = 0;
      sprintf(puffer2,"%d",dazu);
      strcat(puffer,puffer2);
      uint32_t stelle = StreuFunktion(puffer,strlen(puffer)) % nZahlen;
      zaehlerFeld.at(stelle)++;
   }
   druckeHistogramm(zaehlerFeld,200);
}

void PruefungZeichenkettenLang(uint32_t (*StreuFunktion)(const void*,size_t groesse) )
{
    
   char puffer[200];
   strcpy(puffer,"AntonBmannAntonBmannAntonBmannAntonBmannAntonBmannAntonBmannAntonBmannAntonBmann"); 
   vector<uint32_t> zaehlerFeld;
   zaehlerFeld.resize(nZahlen);

   setzeNull(zaehlerFeld);

   uint32_t lB = strlen(puffer);
   for(uint32_t i=0; i < nZahlen; i++)
   {
      uint32_t dazu = i*1017/11;
      char puffer2[11];
      puffer[lB] = 0;
      sprintf(puffer2,"%d",dazu);
      strcat(puffer,puffer2);

      uint32_t stelle = StreuFunktion(puffer,strlen(puffer)) % nZahlen;
      zaehlerFeld.at(stelle)++;
   }
   druckeHistogramm(zaehlerFeld,200);
}

 

uint32_t suchoi_void(const void* input, size_t input_size)
{
   return suchoi((const char*)input, input_size);
}

unsigned int MurmurHash2 ( const void * key, int len, unsigned int seed )
{
	// 'm' and 'r' are mixing constants generated offline.
	// They're not really 'magic', they just happen to work well.

	const unsigned int m = 0x5bd1e995;
	const int r = 24;

	// Initialize the hash to a 'random' value

	unsigned int h = seed ^ len;

	// Mix 4 bytes at a time into the hash

	const unsigned char * data = (const unsigned char *)key;

	while(len >= 4)
	{
		unsigned int k = *(unsigned int *)data;

		k *= m; 
		k ^= k >> r; 
		k *= m; 
		
		h *= m; 
		h ^= k;

		data += 4;
		len -= 4;
	}
	
	// Handle the last few bytes of the input array

	switch(len)
	{
	   case 3: h ^= data[2] << 16;
	   case 2: h ^= data[1] << 8;
	   case 1: h ^= data[0];
	           h *= m;
	};

	// Do a few final mixes of the hash to ensure the last few
	// bytes are well-incorporated.

	h ^= h >> 13;
	h *= m;
	h ^= h >> 15;

	return h;
} 


uint32_t  MurmurHash2_streusumme ( const void * key, size_t len)
{
   return MurmurHash2(key,len,1234567);
}


/*this functions is allegedly from Paul Larson, Microsoft Research */
uint32_t PaulLarsonStreu(const void* s, size_t lenOktets)
{
    uint32_t h = 1234567;
    const uint8_t* zeigerOktets = (const uint8_t*)s;
    for(size_t stelle=0; stelle < lenOktets; stelle++)
    {
        h = h * 101 + (unsigned) zeigerOktets[stelle];
    }
    return h;
}


/*Cyclic Redundancy Check 32 */
uint32_t crc32b(const void* messageVoid,size_t len) 
{
   
   uint32_t byte, crc, mask;

   char* message = (char*)messageVoid;

   
   crc = 0xFFFFFFFF;
   for(size_t i=0; i < len; i++) 
   {
      byte = message[i];            // Get next byte.
      crc = crc ^ byte;
      for (int8_t j = 7; j >= 0; j--) 
      {    // Do eight times.
         mask = -(crc & 1);
         crc = (crc >> 1) ^ (0xEDB88320 & mask);
      }
   }
   return uint32_t(~crc);
}


//PJW
uint32_t PJW_ElfHash ( const void* vs,size_t len )
{
    const char* s = (const char*) vs;
    unsigned long   h = 0, high;
    for(size_t i=0; i < len; i++)
    {
        h = ( h << 4 ) + s[i];
        high = h & 0xF0000000;
        if ( high )
        {
            h ^= high >> 24;
        }
        h &= ~high;
    }
    return h;
}


uint32_t jenkins_one_at_a_time_hash(const void* vkey, size_t length) 
{
  const char* key = (const char*)vkey;
  size_t i = 0;
  uint32_t hash = 0;
  while (i != length) 
  {
    hash += key[i++];
    hash += hash << 10;
    hash ^= hash >> 6;
  }
  hash += hash << 3;
  hash ^= hash >> 11;
  hash += hash << 15;
  return hash;
}

//Einfache Funktion von Frank Gerlach mit guter Qualität, aber nicht der besten Laufzeit
uint32_t FGMult(const void* vkey, size_t length) 
{
  const char* key = (const char*)vkey;

  uint32_t zustand = 123456789;

  for(size_t i=0; i < length; i++)
  {
     zustand = (zustand * key[i] *(i+1))  + (zustand >> 7) ;
     zustand = (zustand*987651)+ (zustand >> 17) ;
  }  

  return zustand;
}

uint32_t FGMult_ww(const void* vkey, size_t length) 
{

  uint64_t zustand = 123456789123456789ll;

  const uint64_t* zeiger = (uint64_t*)vkey;

  while(length >= 8 )
  {
      zustand = zustand * (*zeiger) + (zustand >> 28);
      zustand = (zustand*987651987651)+ (zustand >> 34) ;
      zeiger++;
      length -=8;
  }  
 
  zustand ^= FGMult(zeiger,length);

  

  return uint32_t(zustand);
}

uint32_t FG_ww_shift(const void* vkey, size_t length) 
{

  uint64_t zustand = 123456789123456789ll;

  const uint64_t* zeiger = (uint64_t*)vkey;

  while(length >= 8 )
  {
      zustand = zustand + (*zeiger);
      zustand += zustand << 20;
      zustand ^= zustand >> 12;

      zeiger++;
      length -=8;
  }  
  zustand ^= FGMult(zeiger,length);

  zustand += zustand << 6;
  zustand ^= zustand >> 22;
  zustand += zustand << 30;

  return uint32_t(zustand);
}

extern uint32_t crc32_messagecalc2(const void *data, size_t len);//zweite CRC Implementierung zur Kontrolle

void pruefProzedur( uint32_t (*StreuFunktion)(const void*,size_t groesse), const char* nameStreufunktion)
{
    cout << "=========================================================================================" << endl;
    cout << nameStreufunktion << ":" << endl;
    cout << "Zahlen zusammenhaengend: " << endl << endl;
    PruefungZahlen(StreuFunktion);
    cout << "======================================" << endl;
    cout << "Zahlen im Abstand 100: " << endl;
    PruefungZahlenAbstand(StreuFunktion);
    cout << "======================================" << endl;
    cout << "Zeichenketten: " << endl;
    PruefungZeichenketten(StreuFunktion);
    cout << "======================================" << endl;
    cout << "Zeichenketten lang: " << endl;
    PruefungZeichenkettenLang(StreuFunktion);
}



int main(int argc, char** argv)
{
   uint32_t GroesseFeld = atoi(argv[1]);
   nZahlen  = GroesseFeld;
   int szenario = atoi(argv[2]);

  
   switch(szenario)
   {
       case 0:
               pruefProzedur(suchoi_void,"Suchoi");               
       break;

       case 1: 
               pruefProzedur(sha256_streusumme,"SHA256"); 
       break;

       case 2:     
               pruefProzedur(adler32,"Adler32");  
       break;
       
       case 3: 
               pruefProzedur(MurmurHash2_streusumme,"MurmurHash");     
       break;

       case 4: 
               pruefProzedur(PaulLarsonStreu,"Paul Larson");          
       break;
       
       case 5:
               pruefProzedur(crc32b,"CRC32");    
       break;
       case 6:
               pruefProzedur(PJW_ElfHash,"PJW");
       break;
       case 7:
               pruefProzedur(FGMult,"FGMult");
       break;
       case 8:
               pruefProzedur(FGMult_ww,"FGMult_ww");
       break;

       case 9:
               pruefProzedur(FG_ww_shift,"FG_ww_shift");               
       break;

   }

   return 0;
}
