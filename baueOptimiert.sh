g++ -Wall -O2  -I. -I../suchoi_hash/ -I../crypto-algorithms/\
     ../suchoi_hash/suchoi.c \
     Pruefung.cpp \
     Adler32.c \
     ../crypto-algorithms/sha256.c \
     crc_mcn.c \
     -o SFPruefung
