g++ -Wall -g  -I. -I../suchoi_hash/ -I../crypto-algorithms/\
     ../suchoi_hash/suchoi.c \
     Pruefung.cpp \
     Adler32.c \
     ../crypto-algorithms/sha256.c \
     -o SFPruefung
