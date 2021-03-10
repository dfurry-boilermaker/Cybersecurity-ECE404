#!/usr/bin/python3

###  rsa.py
###  Homework 6
###  Daniel Furry  (danielf@purdue.edu)
###  ECN Login: danielf
###  Due Date: March 9nd, 2021

import random
import sys
from BitVector import *

############################  class PrimeGenerator  ##############################
class PrimeGenerator( object ):                                                    #(A1)

    def __init__( self, **kwargs ):                                          #(A2)
        bits = debug = None                                                  #(A3)
        if 'bits' in kwargs  :     bits = kwargs.pop('bits')                 #(A4)
        if 'debug' in kwargs :     debug = kwargs.pop('debug')               #(A5)
        self.bits            =     bits                                      #(A6)
        self.debug           =     debug                                     #(A7)
        self._largest        =     (1 << bits) - 1                           #(A8)

    def set_initial_candidate(self):                                         #(B1)
        candidate = random.getrandbits( self.bits )                          #(B2)
        if candidate & 1 == 0: candidate += 1                                #(B3)
        candidate |= (1 << self.bits-1)                                      #(B4)
        candidate |= (2 << self.bits-3)                                      #(B5)
        self.candidate = candidate                                           #(B6)

    def set_probes(self):                                                    #(C1)
        self.probes = [2,3,5,7,11,13,17]                                     #(C2)

    # This is the same primality testing function as shown earlier
    # in Section 11.5.6 of Lecture 11:
    def test_candidate_for_prime(self):                                      #(D1)
        'returns the probability if candidate is prime with high probability'
        p = self.candidate                                                   #(D2)
        if p == 1: return 0                                                  #(D3)
        if p in self.probes:                                                 #(D4)
            self.probability_of_prime = 1                                    #(D5)
            return 1                                                         #(D6)
        if any([p % a == 0 for a in self.probes]): return 0                  #(D7)
        k, q = 0, self.candidate-1                                           #(D8)
        while not q&1:                                                       #(D9)
            q >>= 1                                                          #(D10)
            k += 1                                                           #(D11)
        if self.debug: print("q = %d  k = %d" % (q,k))                       #(D12)
        for a in self.probes:                                                #(D13)
            a_raised_to_q = pow(a, q, p)                                     #(D14)
            if a_raised_to_q == 1 or a_raised_to_q == p-1: continue          #(D15)
            a_raised_to_jq = a_raised_to_q                                   #(D16)
            primeflag = 0                                                    #(D17)
            for j in range(k-1):                                             #(D18)
                a_raised_to_jq = pow(a_raised_to_jq, 2, p)                   #(D19)
                if a_raised_to_jq == p-1:                                    #(D20)
                    primeflag = 1                                            #(D21)
                    break                                                    #(D22)
            if not primeflag: return 0                                       #(D23)
        self.probability_of_prime = 1 - 1.0/(4 ** len(self.probes))          #(D24)
        return self.probability_of_prime                                     #(D25)

    def findPrime(self):                                                     #(E1)
        self.set_initial_candidate()                                         #(E2)
        if self.debug:  print("    candidate is: %d" % self.candidate)       #(E3)
        self.set_probes()                                                    #(E4)
        if self.debug:  print("    The probes are: %s" % str(self.probes))   #(E5)
        max_reached = 0                                                      #(E6)
        while 1:                                                             #(E7)
            if self.test_candidate_for_prime():                              #(E8)
                if self.debug:                                               #(E9)
                    print("Prime number: %d with probability %f\n" %       
                          (self.candidate, self.probability_of_prime) )      #(E10)
                break                                                        #(E11)
            else:                                                            #(E12)
                if max_reached:                                              #(E13)
                    self.candidate -= 2                                      #(E14)
                elif self.candidate >= self._largest - 2:                    #(E15)
                    max_reached = 1                                          #(E16)
                    self.candidate -= 2                                      #(E17)
                else:                                                        #(E18)
                    self.candidate += 2                                      #(E19)
                if self.debug:                                               #(E20)
                    print("    candidate is: %d" % self.candidate)           #(E21)
        return self.candidate                                                #(E22)

##################################################################################

def generate(): 
    e = 65537
    p = 0
    q = 0
    #generate p and q and make sure they meet all the requirements
    while p == 0 and q == 0:
        num_of_bits_desired = int(128)                                             #(M3)
        generator = PrimeGenerator( bits = num_of_bits_desired )                   #(M4)
        p_prime = generator.findPrime()                                            #(M5)
        q_prime = generator.findPrime()
    
        p_test = p_prime - 1
        q_test = q_prime - 1

        #check that p and q are not equal
        if p_prime != q_prime:
            while e: #calculate GCD between e & p                                   
                p_test,e = e, p_test%e

            e = 65537
            while e: #calculate GCD between e & q                                     
                q_test,e = e, q_test%e

        #if both GCD's equal 1 assign p and q
        if p_test == 1 and q_test == 1:
            p = p_prime
            q = q_prime
        
        return p,q

def encrypt(message,p,q):
    e = 65537
    n = p * q
    full_size = message.length()
    encrypt_final = BitVector(size=0)
    x=0
    
    #encrypt the message through rsa
    while x < full_size:
        
        if x + 128 <= full_size:
            y = x + 128
        else:
            y = full_size

        #set current block
        curr_bitvec = message[x:y]
        
        #padding with 0's if necessary
        if curr_bitvec.length() < 128:
            pad_num = 128 - curr_bitvec.length()
            curr_bitvec.pad_from_right(pad_num)

        #pad from left and combine bitvec
        encrypted = pow(curr_bitvec.int_val(),e,n)
        encrypt_test = BitVector(intVal=encrypted, size=256)
        encrypt_final += encrypt_test

        x += 128

    return encrypt_final

def decrypt(encrypted,p,q):
    e = 65537
    x=0
    n = p * q
    full_size = encrypted.length()
    bv_e = BitVector(intVal = e)
    totient = (p-1) * (q-1)
    bv_totient = BitVector(intVal = totient)
    bv_d = bv_e.multiplicative_inverse(bv_totient)
    d = bv_d.int_val()
    decrypted_final = BitVector(size=0)


    #decrypt the encrypted file through rsa
    while x < full_size:

        #select block for encryption
        if x + 256 <= full_size:
            y = x + 256
        else:
            y = full_size

        #set current block
        curr_bitvec = encrypted[x:y]

        #select only the non-padded part of each block and combine bitvector 
        decrypted = pow(curr_bitvec.int_val(),d,n)
        decrypt_test = BitVector(intVal=decrypted, size=256)
        decrypted_final += decrypt_test[128:]

        x += 256

    return decrypted_final


if __name__ == '__main__':
    
    if sys.argv[1] == str('-g'): #-g argument calls the generate function
        p,q = generate()
        p1 = str(p)
        prime1 = open(sys.argv[2], 'w') 
        prime1.write(p1)
        q1 = str(q)
        prime2 = open(sys.argv[3], 'w') 
        prime2.write(q1)

    if sys.argv[1] == str('-e'): #-e argument calls the encrypt function
        #read in files 
        FILE_M = open(sys.argv[2])
        message_i = FILE_M.read()
        bv_message = BitVector(textstring = message_i)
        
        FILE_P1 = open(sys.argv[3])
        p1 = int(FILE_P1.read())

        FILE_q1 = open(sys.argv[4])
        q1 = int(FILE_q1.read())

        #call the encrypt function
        final = encrypt(bv_message,p1,q1)

        #write out to the file in hex
        cipher_hex = final.get_bitvector_in_hex()
        encrypted = open(sys.argv[5], 'w')  
        encrypted.write(cipher_hex)

    if sys.argv[1] == str('-d'): #-d argument calls the decrypt function
        #read in files
        FILE_M = open(sys.argv[2])
        encrypted_i = FILE_M.read()
        bv_encrypted = BitVector(hexstring = encrypted_i)
        
        FILE_P1 = open(sys.argv[3])
        p1 = int(FILE_P1.read())

        FILE_P2 = open(sys.argv[4])
        p2 = int(FILE_P2.read())

        #call the decrypt function
        final = decrypt(bv_encrypted,p1,p2)

        #write out to the file in ascii
        plain_hex = final.get_bitvector_in_ascii()
        encrypted = open(sys.argv[5], 'w')  
        encrypted.write(plain_hex)
