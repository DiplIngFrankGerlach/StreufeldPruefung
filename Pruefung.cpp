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

/* Feld mit sehr grosser Anzahl von 3bit-Zaehlern */
class Zaehlerfeld3bit
{
   uint8_t* m_rohFeld;
   uint64_t m_groesse;
public:
   Zaehlerfeld3bit(uint64_t groesse):m_groesse(groesse)
   {
       uint64_t anzahlOktets = 3*m_groesse/8 + 1;
       m_rohFeld = new uint8_t[anzahlOktets];
       sichere( m_rohFeld != NULL, "Speicher anlegen"); 
       memset(m_rohFeld,0,anzahlOktets);
   }

   uint8_t bei(uint64_t stelle)
   {
      if( stelle < m_groesse )
      {
         uint64_t bitStelle = stelle * 3;
         uint64_t oktetStelle = bitStelle / 8;
         uint8_t versatz = bitStelle % 8;
         if( versatz < 6 )
         {
             return (m_rohFeld[oktetStelle] >> versatz) & 0x7;
         }
         else
         {
             
             uint8_t oktetLinks = m_rohFeld[oktetStelle];
             uint8_t oktetRechts = m_rohFeld[oktetStelle+1];
             oktetLinks >>= versatz;
             oktetRechts <<= (8-versatz);
             
             uint8_t oktetGesamt = (oktetLinks | oktetRechts) & 0x7;
             return oktetGesamt;
         }
      }
      sichere(false,"gueltige Stelle");
      return 0xFF;
   }

   void setze(uint64_t stelle, uint8_t wert)
   {
      sichere(stelle < m_groesse,"index gueltig");
      sichere(wert < 8,"Wertebereich");
      uint64_t bitStelle = stelle * 3;
      uint64_t oktetStelle = bitStelle / 8;
      uint8_t versatz = bitStelle % 8;

      uint8_t maske = 0x7;
      maske <<= versatz;
      maske ^= 0xFF;
      if( versatz < 6 )
      {
          wert <<= versatz;
          uint8_t altWert = m_rohFeld[oktetStelle];
          
          altWert &= maske;
          altWert |= wert;
          m_rohFeld[oktetStelle] = altWert;
      }
      else
      {
          uint8_t altWertLinks = m_rohFeld[oktetStelle];
          altWertLinks &= maske;
          altWertLinks |= (wert << versatz);
          m_rohFeld[oktetStelle] = altWertLinks;
          uint8_t altWertRechts = m_rohFeld[oktetStelle+1];
          uint8_t maskeRechts = 0x7;
          maskeRechts >>= (8-versatz); 
          maskeRechts ^= 0xFF;
          altWertRechts &= maskeRechts;          
          altWertRechts |= (wert >> (8-versatz));
          m_rohFeld[oktetStelle+1] = altWertRechts;
      }
   }

   void zaehleHoch(uint64_t stelle)
   {
      uint8_t wert = bei(stelle);
      if( wert < 7 )
      {
         wert++;
         setze(stelle,wert);
      }
   }

   ~Zaehlerfeld3bit()
   {
      delete[] m_rohFeld;
      m_rohFeld = NULL;
   }
    
};

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

uint32_t nZahlen = 1000000;

void druckeHistogramm(vector<uint32_t>& zaehlerFeld, uint32_t maxHaeufigkeit)
{
   vector<uint32_t> histogramm;
   histogramm.resize(maxHaeufigkeit+1);
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
   cout << "mehr als " << maxHaeufigkeit << " " << histogramm.at(maxHaeufigkeit) << endl;
}



void PruefungZahlen( uint32_t (*StreuFunktion)(const void*,size_t groesse) )
{
    
   vector<uint32_t> zaehlerFeld;
   zaehlerFeld.resize(nZahlen);
   for(uint32_t i=0; i < nZahlen; i++)
   {
      uint32_t stelle = StreuFunktion(&i,sizeof(uint32_t));
      zaehlerFeld.at(stelle%nZahlen)++;
   }
   druckeHistogramm(zaehlerFeld,200);
}

/*Pruefalgorithmus mit Zahlen im Abstand von 100 */
void PruefungZahlenAbstand( uint32_t (*StreuFunktion)(const void*,size_t groesse) )
{
   cout << "Pruefung Zahlen mit Abstand 100" << endl; 
   vector<uint32_t> zaehlerFeld;
   zaehlerFeld.resize(nZahlen);
   for(uint32_t i=0; i < nZahlen; i++)
   {
      uint32_t pruefZahl = i * 100;
      uint32_t stelle = StreuFunktion(&pruefZahl,sizeof(uint32_t));
      zaehlerFeld.at(stelle%nZahlen)++;
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
   for(uint32_t i=0; i < nZahlen; i++)
   {
      uint32_t dazu = i*1017/11;
      char puffer2[11];
      puffer[10] = 0;
      sprintf(puffer2,"%d",dazu);
      strcat(puffer,puffer2);

      //cout << puffer << endl;

      uint32_t stelle = StreuFunktion(puffer,strlen(puffer));
      zaehlerFeld.at(stelle%nZahlen)++;
   }
   druckeHistogramm(zaehlerFeld,200);
}

void PruefungZeichenkettenLang(uint32_t (*StreuFunktion)(const void*,size_t groesse) )
{
    
   char puffer[200];
   strcpy(puffer,"AntonBmannAntonBmannAntonBmannAntonBmannAntonBmannAntonBmannAntonBmannAntonBmann"); 
   vector<uint32_t> zaehlerFeld;
   zaehlerFeld.resize(nZahlen);

   uint32_t lB = strlen(puffer);
   for(uint32_t i=0; i < nZahlen; i++)
   {
      uint32_t dazu = i*1017/11;
      char puffer2[11];
      puffer[lB] = 0;
      sprintf(puffer2,"%d",dazu);
      strcat(puffer,puffer2);

      //cout << puffer << endl;

      uint32_t stelle = StreuFunktion(puffer,strlen(puffer));
      zaehlerFeld.at(stelle%nZahlen)++;
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

extern uint32_t crc32_messagecalc2(const void *data, size_t len);//zweite CRC Implementierung zur Kontrolle



int main(int argc, char** argv)
{
   int szenario = atoi(argv[1]);

   const int n=100;
   Zaehlerfeld3bit zf3(n);
   for(int i=0; i < n; i++)
   {
      zf3.setze(i,i%8);
   }
   for(int i=0; i < n; i++)
   {
      assert(zf3.bei(i) == (i%8));
   }

   switch(szenario)
   {
       case 0:
               cout << "Suchoi: " << endl;
               PruefungZahlen(suchoi_void);
               PruefungZahlenAbstand(suchoi_void);
               PruefungZeichenkettenLang(suchoi_void);
       break;

       case 1:
               cout << "SHA256: " << endl;
               PruefungZahlen(sha256_streusumme);
               PruefungZahlenAbstand(sha256_streusumme);
       break;

       case 2:      
               cout << "Adler32(Zahlen): " << endl;
               PruefungZahlen(adler32);
               PruefungZahlenAbstand(adler32);
       break;
       case 3:      
               cout << "Suchoi(Zeichenketten): " << endl;
               PruefungZeichenketten(suchoi_void);
       break;
       case 4:      
               cout << "SHA256(Zeichenketten): " << endl;
               PruefungZeichenketten(sha256_streusumme);
       break;
       case 5:      
               cout << "Adler32(Zeichenketten): " << endl;
               PruefungZeichenketten(adler32);
       break;
       case 6:      
               cout << "Murmurhash: " << endl;
               PruefungZeichenketten(MurmurHash2_streusumme);
       break;

       case 7:      
               cout << "Paul Larson (Zeichenketten): " << endl;
               PruefungZeichenketten(PaulLarsonStreu);
       break;
       case 8:
               cout << "Paul Larson (Zahlen): " << endl;
               PruefungZahlen(PaulLarsonStreu);
               PruefungZahlenAbstand(PaulLarsonStreu);
       break;
       case 9:
               cout << "CRC32 (Zahlen): " << endl;
               PruefungZahlen(crc32b);
               PruefungZahlenAbstand(crc32b);
               cout << "CRC32 (Zeichenkette): " << endl;
               PruefungZeichenketten(crc32b);
       break;
       case 10:
               cout << "CRC32_2 (Zahlen): " << endl;
               PruefungZahlen(crc32_messagecalc2);
               PruefungZahlenAbstand(crc32_messagecalc2);
               cout << "CRC32 (Zeichenkette): " << endl;
               PruefungZeichenketten(crc32_messagecalc2);
       break;
       case 11:
               cout << "PJW (Zahlen): " << endl;
               PruefungZahlen(PJW_ElfHash);
               PruefungZahlenAbstand(PJW_ElfHash);
               cout << "PJW (Zeichenkette): " << endl;
               PruefungZeichenketten(PJW_ElfHash);
       break;
       case 12:
               cout << "Jenkins One At A Time (Zahlen): " << endl;
               PruefungZahlen(jenkins_one_at_a_time_hash);
               PruefungZahlenAbstand(jenkins_one_at_a_time_hash);
               cout << "Jenkins One At A Time (Zeichenkette): " << endl;
               PruefungZeichenketten(jenkins_one_at_a_time_hash);
       break;

       case 13:
               cout << "FGMult (Zahlen): " << endl;
               PruefungZahlen(FGMult);
               PruefungZahlenAbstand(FGMult);
               cout << "FGMult (Zeichenkette): " << endl;
               PruefungZeichenketten(FGMult);
               PruefungZeichenkettenLang(FGMult);
       break;




   }

   return 0;
}
