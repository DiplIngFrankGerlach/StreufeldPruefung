#ifndef ZAEHLERFELD_3BIT
#define ZAEHLERFELD_3BIT

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

#endif
