/* Testcode zur Bewertung verschiedener Hashfunktionen */

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

uint32_t nZahlen = 100000000;

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




void PruefungZahlen(uint32_t (*StreuFunktion)(const void*,size_t groesse) )
{
    
   Zaehlerfeld3bit zf3(nZahlen);
   for(uint32_t i=0; i < nZahlen; i++)
   {
      uint32_t stelle = StreuFunktion(&i,sizeof(uint32_t));
      zf3.zaehleHoch(stelle%nZahlen);
   }

   uint64_t histogramm[8];
   memset(histogramm,0,8*sizeof(uint64_t));
   for(uint32_t i=0; i < nZahlen; i++)
   {       
      uint8_t wert = zf3.bei(i);
      histogramm[wert]++;
   }
    
   cout << "Haeufigkeiten:" << endl;
   uint64_t summe(0);
   for(uint8_t j=0; j < 7; j++)
   {
      summe += histogramm[j];
      cout << uint32_t(j) << " " << histogramm[j] << endl;
   }  
   cout << "7 und mehr " << histogramm[7] << endl;
   
}

void PruefungZahlenAdler32()
{
    
   vector<uint32_t> zaehlerFeld;
   zaehlerFeld.resize(nZahlen);
   for(uint32_t i=0; i < nZahlen; i++)
   {
      uint32_t stelle = adler32(&i,sizeof(uint32_t));
      zaehlerFeld.at(stelle%nZahlen)++;
   }
   cout << "Adler32" << endl;
   druckeHistogramm(zaehlerFeld,200);
}

uint32_t suchoi_void(const void* input, size_t input_size)
{
   return suchoi((const char*)input, input_size);
}



int main()
{
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

   cout << "Suchoi: " << endl;
   PruefungZahlen(suchoi_void);

   cout << "SHA256: " << endl;
   PruefungZahlen(sha256_streusumme);

   PruefungZahlenAdler32();
}
