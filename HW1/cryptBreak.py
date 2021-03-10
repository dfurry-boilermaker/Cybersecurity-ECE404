#/usr/bin/python3

###  cryptBreak.py
###  Daniel Furry  (danielf@purdue.edu)
###  January 23, 2021

from BitVector import *  
def cryptBreak(ciphertextFile,key_bv):
    
    PassPhrase = "Hopes and dreams of a million years"                          #(C)

    BLOCKSIZE = 16                                                              #(D)
    numbytes = BLOCKSIZE // 8                                                   #(E)

    # Reduce the passphrase to a bit array of size BLOCKSIZE:
    bv_iv = BitVector(bitlist = [0]*BLOCKSIZE)                                  #(F)
    for i in range(0,len(PassPhrase) // numbytes):                              #(G)
        textstr = PassPhrase[i*numbytes:(i+1)*numbytes]                         #(H)
        bv_iv ^= BitVector( textstring = textstr )                              #(I)

    # Create a bitvector from the ciphertext hex string:
    FILEIN = open(ciphertextFile)                                               #(J)
    encrypted_bv = BitVector( hexstring = FILEIN.read() )                       #(K)

    # Create a bitvector for storing the decrypted plaintext bit array:
    msg_decrypted_bv = BitVector( size = 0 )                                    #(T)

    # Carry out differential XORing of bit blocks and decryption:
    previous_decrypted_block = bv_iv                                            #(U)
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):                          #(V)
        bv = encrypted_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE]                          #(W)
        temp = bv.deep_copy()                                                   #(X)
        bv ^=  previous_decrypted_block                                         #(Y)
        previous_decrypted_block = temp                                         #(Z)
        bv ^=  key_bv                                                           #(a)
        msg_decrypted_bv += bv                                                  #(b)

    # Extract plaintext from the decrypted bitvector:    
    outputtext = msg_decrypted_bv.get_text_from_bitvector()                     #(c)                                                         #(f)
    return outputtext

if __name__ == '__main__':
    testKey = 0
    # Brute force loop
    while testKey < 65536:
        key_bv = BitVector(intVal=testKey, size=16)
        decryptedMessage = cryptBreak('encrypted.txt', key_bv)
        # Checking for the string 'Yogi Berra'
        if 'Yogi Berra' in decryptedMessage:
            print('Encryption Broken!')
            print(decryptedMessage)
            print ('The encryption key is: ' + str(testKey))
            break
        else: 
            testKey = testKey + 1
        if testKey % 2000 == 0:
            print('Not decrypted yet; Key: ' + str(testKey))
