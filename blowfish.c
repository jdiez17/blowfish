#include <stdio.h>
#include <stdlib.h>

#include "blowfish.h"

void swap(uint32_t* a, uint32_t* b) {
    uint32_t tmp;
    
    tmp = *a;
    *a = *b;
    *b = tmp;
}

uint32_t blowfish_f(blowfish_t* container, uint32_t input) {
    uint8_t a, b, c, d;
    
    a = input >> 24;
    b = (input >> 16) & 0xff;
    c = (input >> 8) & 0xff;
    d = input & 0xff;
    
    return ((container->s[0][a] + container->s[1][b]) ^ container->s[2][c]) +
            container->s[3][d];
}

void blowfish_cipher(blowfish_t* container, uint32_t* xl, uint32_t* xr, uint8_t mode) {
    int i;
    uint32_t loc_xl, loc_xr;
    
    loc_xl = *xl;
    loc_xr = *xr;
    
    if(mode == BLOWFISH_ENCRYPT) {
        for(i = 0; i < PASSES; i++) {
            loc_xl = loc_xl ^ container->p[i];
            loc_xr = blowfish_f(container, loc_xl) ^ loc_xr;
        
            swap(&loc_xl, &loc_xr);
        }
    } else if(mode == BLOWFISH_DECRYPT) {
        for(i = PASSES+1; i > 1; i--) {
            loc_xl = loc_xl ^ container->p[i];
            loc_xr = blowfish_f(container, loc_xl) ^ loc_xr;
        
            swap(&loc_xl, &loc_xr);
        }
    }
        
    swap(&loc_xl, &loc_xr);
    
    if(mode == BLOWFISH_ENCRYPT) { 
        loc_xr = loc_xr ^ container->p[PASSES];
        loc_xl = loc_xl ^ container->p[PASSES+1];
    } else if(mode == BLOWFISH_DECRYPT) {
        loc_xr = loc_xr ^ container->p[1];
        loc_xl = loc_xl ^ container->p[0];
    }
    
    *xl = loc_xl;
    *xr = loc_xr;
}

blowfish_t* blowfish_initialize(unsigned char* key, uint32_t length) {
    blowfish_t* container = malloc(sizeof(blowfish_t));
    unsigned int i, ii, j = 0;
    uint32_t tmp, tmp_l = 0, tmp_r = 0;  

    if(length > BLOWFISH_MAX_KEY_BYTES) return (blowfish_t*) NULL;

    for(i = 0; i < PASSES+2; i++) {
        container->p[i] = P[i];
    }
    
    for(i = 0; i < SBOXES; i++) {
        for(ii = 0; ii < 256; ii++) {
            container->s[i][ii] = S[i][ii];
        }
    }
    
    for(i = 0; i < PASSES+2; i++) {
        tmp = 0;
        for(ii = 0; ii < 4; ii++) {
            tmp = (tmp << 8) | key[j];
            j++;
            if(j == length) 
                j = 0;
        }
        container->p[i] = container->p[i] ^ tmp;
    }

    for(i = 0; i < PASSES+1; i += 2) {
        blowfish_cipher(container, &tmp_l, &tmp_r, BLOWFISH_ENCRYPT);
        container->p[i] = tmp_l;
        container->p[i+1] = tmp_r;
    }
    
    for(i = 0; i < SBOXES; i++) {  
        for(ii = 0; ii < 256; ii += 2) { 
            blowfish_cipher(container, &tmp_l, &tmp_r, BLOWFISH_ENCRYPT);
            container->s[i][ii] = tmp_l;
            container->s[i][ii+1] = tmp_r;
        }
    }
}

int main(int argc, char** argv) {
    uint32_t high, low;
    blowfish_t* container = blowfish_initialize("test", 4);

    high = 0xc0debabe;
    low = 0xdeadbeef;
    blowfish_cipher(container, &high, &low, BLOWFISH_ENCRYPT);
    printf("high: %x low: %x\n", high, low);
    return 0;
}
