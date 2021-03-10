#!/usr/bin/python3

###  rsa.py
###  Homework 6
###  Daniel Furry  (danielf@purdue.edu)
###  ECN Login: danielf
###  Due Date: March 9nd, 2021

import random
import sys
from BitVector import *
from solve_pRoot_BST import solve_pRoot

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
    e = 3
    p = 0
    q = 0

    #generate p and q and make sure they meet all the requirements
    while p == 0 and q == 0:
        #print(e)
        num_of_bits_desired = int(128)                                             #(M3)
        generator = PrimeGenerator( bits = num_of_bits_desired )                   #(M4)
        p_prime = generator.findPrime()                                            #(M5)
        q_prime = generator.findPrime()
    
        #print("here")

        p_test = p_prime - 1
        q_test = q_prime - 1

        #check that p and q are not equal
        if p_prime != q_prime:
            e = 3
            while e: #calculate GCD between e & p                               
                p_test,e = e, p_test%e
                #print(e)

            e = 3
            while e: #calculate GCD between e & q                                     
                q_test,e = e, q_test%e

            #if both GCD's equal 1 assign p and q
            if p_test == 1 and q_test == 1:
                p = p_prime
                q = q_prime
        
    return p,q

def encrypt(message,p,q):
    e = 3
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

    return encrypt_final, n

def decrypt(enc1,enc2,enc3,n123,N,d123):
    x=0
    full_size = enc1.length()
    decrypted_final = BitVector(size=0)


    #decrypt the encrypted file through rsa
    while x < full_size:
        print(x)
        #select block for encryption
        if x + 256 <= full_size:
            y = x + 256
        else:
            y = full_size

        #set current block
        curr_bitvec1 = enc1[x:y]
        curr_bitvec2 = enc2[x:y]
        curr_bitvec3 = enc3[x:y]

        Z = curr_bitvec1.int_val() * n123[0].int_val() * d123[0].int_val() + curr_bitvec2.int_val() * n123[1].int_val() * d123[1].int_val() + curr_bitvec3.int_val() * n123[2].int_val() * d123[2].int_val()

        f_value = Z % N

        block = solve_pRoot(3,f_value)
        decrypt_test = BitVector(intVal=block, size=256)
        decrypted_final += decrypt_test[128:]   

        x += 256

    return decrypted_final

if __name__ == '__main__':

    if sys.argv[1] == str('-e'): #-e argument calls the encrypt function
        #read in files 
        FILE_M = open(sys.argv[2])
        message_i = FILE_M.read()
        bv_message = BitVector(textstring = message_i)
        
        #generate 3 sets of p & q's
        p1,q1 = generate()
        p2,q2 = generate()
        p3,q3 = generate()

        print(p1)
        print(q1)

        #call the encrypt function
        final1,n1 = encrypt(bv_message,p1,q1)
        final2,n2 = encrypt(bv_message,p2,q2)
        final3,n3 = encrypt(bv_message,p3,q3)

        #write to n_1_2_3.txt
        FILE_123 = open(sys.argv[6], 'a')
        FILE_123.write(str(n1) +'\n')
        FILE_123.write(str(n2) +'\n')
        FILE_123.write(str(n3) +'\n')

        #write out to the file in hex
        cipher_hex1 = final1.get_bitvector_in_hex()
        encrypted1 = open(sys.argv[3], 'w')  
        encrypted1.write(cipher_hex1)

        cipher_hex2 = final2.get_bitvector_in_hex()
        encrypted2 = open(sys.argv[4], 'w')  
        encrypted2.write(cipher_hex2)

        cipher_hex3 = final3.get_bitvector_in_hex()
        encrypted3 = open(sys.argv[5], 'w')  
        encrypted3.write(cipher_hex3)

    if sys.argv[1] == str('-c'): #-e argument calls the encrypt function
        #read in files 
        FILE_1 = open(sys.argv[2])
        enc_1 = FILE_1.read()
        bv_enc1 = BitVector(hexstring = enc_1)

        FILE_2 = open(sys.argv[3])
        enc_2 = FILE_2.read()
        bv_enc2 = BitVector(hexstring = enc_2)

        FILE_3 = open(sys.argv[4])
        enc_3 = FILE_3.read()
        bv_enc3 = BitVector(hexstring = enc_3)

        FILE_n = open(sys.argv[5])
        n_123 = FILE_n.read().split()

        #calculate n's
        N = int(n_123[0]) * int(n_123[1]) * int(n_123[2])

        N1 = int(n_123[1]) * int(n_123[2])
        bv_N1 = BitVector(intVal = N1)
        
        N2 = int(n_123[0]) * int(n_123[2])
        bv_N2 = BitVector(intVal = N2)
        
        N3 = int(n_123[0]) * int(n_123[1])
        bv_N3 = BitVector(intVal = N3)


        #calculate d's
        bv_d1 = bv_N1.multiplicative_inverse(BitVector(intVal=int(n_123[0])))
        bv_d2 = bv_N2.multiplicative_inverse(BitVector(intVal=int(n_123[1])))
        bv_d3 = bv_N3.multiplicative_inverse(BitVector(intVal=int(n_123[2])))

        N_final = [bv_N1,bv_N2,bv_N3]
        d_final = [bv_d1,bv_d2,bv_d3]
        
        #call the decrypt function
        final = decrypt(bv_enc1, bv_enc2, bv_enc3, N_final, N, d_final)

        #write out to the file in ascii
        plain_hex = final.get_bitvector_in_ascii()
        encrypted = open(sys.argv[6], 'w')  
        encrypted.write(plain_hex)