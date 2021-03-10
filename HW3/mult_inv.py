#!/usr/bin/python3

###  mult_inv.py
###  Daniel Furry  (danielf@purdue.edu)
###  February 07, 2021

import sys

if len(sys.argv) != 3:  
    sys.stderr.write("Usage: %s   <integer>   <modulus>\n" % sys.argv[0]) 
    sys.exit(1) 

NUM, MOD = int(sys.argv[1]), int(sys.argv[2])

def MI(num, mod):

    ''' MI function is taken from FindMI.py which function calls for muliplication and division throughout
    This function finds the Multiplicative inverse of the first-arg integer vis-a-vis the second-arg interger 
    otherwiae finds the GCD... both using bit shift operations of the Extended Euclid's Algorithm '''

    NUM = num
    MOD = mod
    x = 0
    x_old = 1

    while mod:
        q = bitDivide(num, mod) #calls the divide function to correctly perform floor division
        num, mod = mod, num % mod

        x, x_old = x_old - (bitMultiply(q, x)), x #calls multiplication function to compute x factor each iteration

    #when num doesn't = 1, there is no MI so it prints the GCD, otherwise it prints out the MI
    if num != 1:
        print("\nNO MI. However, the GCD of %d and %d is %u\n" % (NUM, MOD, num))
    else:
        MI = (x_old + MOD) % MOD
        print("\nMI of %d modulo %d is: %d\n" % (NUM, MOD, MI))

def bitDivide(dividend, divisor):

    ''' Divide dividend by divisor using the binary representations stored in resultD
    This function was written based on sudocode from buildingblocks cs.vt website '''

    resultD = 0
    i = 0
    shift = 0
    divisor_original = divisor #stores the orignial divisor
    
    #calculates length of each int in binary for pre-shifts
    dividend_len = len(bin(dividend)[2:])
    divisor_len = len(bin(divisor)[2:])

    #shifts either the dividend or divisor to align them
    if dividend_len < divisor_len:
        dividend = dividend >> (divisor_len - dividend_len)
        shift = divisor_len - dividend_len
    elif dividend_len > divisor_len:
        divisor = divisor << (dividend_len - divisor_len)
        shift = dividend_len - divisor_len

    #loop to cycle through each binary value and shift and subtract
    while dividend >= divisor_original:
        if dividend >= divisor:
            dividend = dividend - divisor
            resultD = resultD << 1
            resultD = resultD | 1
        else:
            resultD = resultD << 1
        
        divisor = divisor >> 1
        i += 1

    #shifts to the left (adds a trailing 0's) for exception that misses trailing zeros
    if i <= shift:
        resultD = resultD << (shift - (i-1))
    return resultD

def bitMultiply(a, b):

    ''' multiply a and b using shift and add of binary representations '''

    resultM = 0 
    align = 0
    check = 0

    #checks for negative values passed into the function (subtracts itself twice) - make the numbers positive
    if a < 0: 
        a = a - a - a
        check += 1
    if b < 0:
        b = b - b - b
        check += 1
    if check == 2:
        check = 0

    #loop that shifts the bits to multiply a & b and store it as resultM
    while b and align < 8:
        if b & 1:
            resultM += (a << align)
            
        #increment and shift    
        b = b >> 1
        align += 1

    #makes sure the product is positive 
    if check > 0:
        resultM = resultM - resultM - resultM
    return resultM

MI(NUM, MOD)