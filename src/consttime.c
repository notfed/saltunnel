//
//  consttime.c
//  saltunnel
//

#include "consttime.h"
#include "oops.h"

#define F(i) differentbits |= x[i] ^ y[i];

static int consttime_are_equal_8(const unsigned char* x,
                                 const unsigned char* y)
{
    unsigned int differentbits = 0;
    F(0) F(1) F(2) F(3) F(4) F(5) F(6) F(7)
    return (1 & ((differentbits - 1) >> 8));
}

static int consttime_are_equal_16(const unsigned char* x,
                                  const unsigned char* y)
{
    unsigned int differentbits = 0;
    F(0) F(1) F(2)  F(3)  F(4)  F(5)  F(6)  F(7)
    F(8) F(9) F(10) F(11) F(12) F(13) F(14) F(15)
    return (1 & ((differentbits - 1) >> 8));
}

static int consttime_are_equal_32(const unsigned char* x,
                                  const unsigned char* y)
{
  unsigned int differentbits = 0;
  F(0)  F(1)  F(2)  F(3)  F(4)  F(5)  F(6)  F(7)
  F(8)  F(9)  F(10) F(11) F(12) F(13) F(14) F(15)
  F(16) F(17) F(18) F(19) F(20) F(21) F(22) F(23)
  F(24) F(25) F(26) F(27) F(28) F(29) F(30) F(31)
  return (1 & ((differentbits - 1) >> 8));
}

int consttime_are_equal(const unsigned char* x, const unsigned char* y, unsigned int len) {
    switch(len) {
        case 8:  return consttime_are_equal_8(x,y);
        case 16: return consttime_are_equal_16(x,y);
        case 32: return consttime_are_equal_32(x,y);
    }
    return oops_error("unsupported consttime_are_equal size");
}
