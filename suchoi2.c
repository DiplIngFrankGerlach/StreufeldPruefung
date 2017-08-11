/* Copyright (c) 2016, Frank Gerlach ( Frank_Gerlach@epam.com )
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.
2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

The views and conclusions contained in the software and documentation are those
of the authors.
*/


/*******************************************************
 * The High Performance Hash Function "suchoi", Version 2.
 * 
 * This function will hash ANY data structure so that
 * 
 * A) hash function runtime is acceptable
 * 
 * B) the hash output has very good distribution
 *    NOTE: Linear Congruential Generators do NOT have
 *          this property and will often yield highly 
 *          unbalanced Hash Tables !
 *
 * C) Both runtime and output quality is better than
 *    Adler32, especially on tiny processors 
 *    without hardware divison/modulo logic.
 * 
 * 
 * Note for users: On "large" computers, the s-box
 *      could be made bigger (256 elements) and also
 *      64 bit state could be used.
 *      I do not yet have experimental data how this
 *      affects performance.
 * 
 * 
 * Author: Frank Gerlach, EPAM LLPD, Minsk
 *
 ******************************************************/


#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>

typedef uint32_t (*hashFuncType)(const char*,uint32_t);


// the first digits of PI, use as an s-box (see DES Standard to see what an s-box is)
//  (in short: a highly non-linear function)
const uint32_t c_pi[]=
{
    0x243F6A88,
    0x85A308D3,
    0x3198A2E0,
    0x3707344A,
    0x40938222,
    0x99F31D00,
    0x82EFA98E,
    0xC4E6C894,
    0x52821E63,
    0x8D01377B,
    0xE5466CF3,
    0x4E90C6CC,
    0x0AC29B7C,
    0x97C50DD3,
    0xF84D5B5B,
    0x54709179 };

 

static uint32_t rotate(uint32_t input,uint8_t count)
{
   return (input << count) | (input >> (32 - count));
}



 

/*high performance permutation/diffusion function 

 Named after Barys Shapashnik, engineer. 
*/
static uint32_t shapashnik(uint32_t input,uint32_t key)
{
   //printf("shapashnik i:%x\n",input);
   uint8_t i;
   uint32_t output;
   for(i=0; i < 10;i++)
   {
     uint32_t upper = input >> 16;
     uint32_t lower = input & 0xFFFF;
     output = (lower << 16) | upper;
     output = rotate(output,key & 0x7);
     key = rotate(key,3); 
     input = output;
   }
    
   return output;
}

    
/* efficient hash function. See head of file for details 
 * 
 * Explanation of "inner workings":
 * The S-box, as wide as the state, ensures that a single
 * bit change in the input will on average flip half the
 * bits of the output ("total avalanche effect").
 * 
 * Rotating the state will make sure that successive
 * identical input octets will not cancel each other out.
 * 
 * After 16 octets of input, rotation of the state can no
 * longer ensure that identical input octets will not cancel 
 * each other out. Therefore, we apply the shapashnik permutation
 * function on the state.
 * 
 * (For a 64 bit state, self-hashing would be needed after
 *  32 octets of input)
 *
 * Named after Pavel Suchoi, engineer.
 * */
uint32_t suchoi2(const void* inputVoid, size_t input_size)
{
    const char* input = (const char*)inputVoid;
    uint32_t state = 0;
    uint32_t i;
    for(i=0; i < input_size; i++)
    {
        char octet = input[i];// ^ (uint8_t)state;
        uint8_t upperNibble = octet >>4;
        uint8_t lowerNibble = octet & 0xF;
        state ^= c_pi[upperNibble];
        state = (state << 31) | (state >> 1);//rotate state
        state ^= c_pi[lowerNibble];
        state = (state << 31) | (state >> 1);//rotate state
        if( (i & 0xf) == 0xf )//danger of "xor-cancellation" -> permute the state
        {
            state = shapashnik(state,state);             
        }
    }
    state = state ^ rotate(state,7) ^ rotate(state,15) ^ rotate(state,23) ^ rotate(state,31);//Make sure the entropy is distributed over the entire output
    return state;
}

  

 
