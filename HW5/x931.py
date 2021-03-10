#!/usr/bin/python3

###  x931.py
###  Homework 5
###  Daniel Furry  (danielf@purdue.edu)
###  ECN Login: danielf
###  Due Date: March 2nd, 2021


import sys
from BitVector import *

subBytesTable = []
invSubBytesTable = []
AES_modulus = BitVector(bitstring='100011011')   

def genTables(): #generate subBytesTable and invSubBytesTable
    c = BitVector(bitstring='01100011')
    d = BitVector(bitstring='00000101')
    for i in range(0, 256):
        # For the encryption SBox
        a = BitVector(intVal = i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        # For bit scrambling for the encryption SBox entries:
        a1,a2,a3,a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c
        subBytesTable.append(int(a))
        # For the decryption Sbox:
        b = BitVector(intVal = i, size=8)
        # For bit scrambling for the decryption SBox entries:
        b1,b2,b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        invSubBytesTable.append(int(b))
    return subBytesTable

def gen_key_schedule_256(key_bv): #generate key schedule
    byte_sub_table = genTables()
    #  We need 60 keywords (each keyword consists of 32 bits) in the key schedule for
    #  256 bit AES. The 256-bit AES uses the first four keywords to xor the input
    #  block with.  Subsequently, each of the 14 rounds uses 4 keywords from the key
    #  schedule. We will store all 60 keywords in the following list:
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal = 0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i*32 : i*32 + 32]
    for i in range(8,60):
        if i%8 == 0:
            kwd, round_constant = gee(key_words[i-1], round_constant, byte_sub_table)
            key_words[i] = key_words[i-8] ^ kwd
        elif (i - (i//8)*8) < 4:
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        elif (i - (i//8)*8) == 4:
            key_words[i] = BitVector(size = 0)
            for j in range(4):
                key_words[i] += BitVector(intVal = 
                                 byte_sub_table[key_words[i-1][8*j:8*j+8].intValue()], size = 8)
            key_words[i] ^= key_words[i-8] 
        elif ((i - (i//8)*8) > 4) and ((i - (i//8)*8) < 8):
            key_words[i] = key_words[i-8] ^ key_words[i-1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

def gee(keyword, round_constant, byte_sub_table): #cipher block chaining mode

    '''
    This is the g() function you see in Figure 4 of Lecture 8.
    '''
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def round_keys_first(workingBV, round_keys): #permute the first round with the first/last round key
    full_size = len(workingBV)
    x=0
    y=0
    total_round = BitVector(size=0)

    while x < full_size:
        
        #select block for encryption
        if x + 128 <= full_size:
            y = x + 128
        else:
            y = full_size

        #set current block
        curr_bitvec = workingBV[x:y]
        
        #padding with 0's if necessary
        if curr_bitvec.length() < 128:
            pad_num = 128 - curr_bitvec.length()
            curr_bitvec.pad_from_right(pad_num)
        
        #if sys.argv[1] == str('-e'):
        curr_round = curr_bitvec ^ round_keys[0]
        total_round += curr_round

        '''if sys.argv[1] == str('-d'):
            curr_round = curr_bitvec ^ round_keys[14]
            total_round += curr_round'''

        x += 128
    
    return total_round 

def encrypt(workingBV, round_keys, round_num): #encrypt function to compute main 4 steps of encryption
    full_size = len(workingBV)
    block_1 = BitVector(size=0)
    block_2 = BitVector(size=0)
    block_3 = BitVector(size=0)
    total = BitVector(size=0)
    x=0
    while x < full_size:
        
        #select block for encryption
        if x + 128 <= full_size:
            y = x + 128
        else:
            y = full_size

        #set current block
        curr_bitvec = workingBV[x:y]

        #padding with 0's if necessary
        if curr_bitvec.length() < 128:
            pad_num = 128 - curr_bitvec.length()
            curr_bitvec.pad_from_right(pad_num)

        #Substitute Bytes
        block_1 = sub_bytes(curr_bitvec)

        #Shift Rows
        block_2 = shift_rows(block_1)

        #Mix Columns
        if round_num != 14:
            block_2 = mix_cols(block_2)

        #Add Round Key
        block_3 = round_keys[round_num] ^ block_2
        
        #Concatnate the whole block
        total = total + block_3

        x += 128

    return total

def decrypt(workingBV, round_keys, round_num):
    full_size = len(workingBV)
    block_1 = BitVector(size=0)
    block_2 = BitVector(size=0)
    block_3 = BitVector(size=0)
    total = BitVector(size=0)
    x=0
    while x < full_size:
        
        #select block for encryption
        if x + 128 <= full_size:
            y = x + 128
        else:
            y = full_size

        #set current block
        curr_bitvec = workingBV[x:y]
        
        #padding with 0's if necessary
        if curr_bitvec.length() < 128:
            pad_num = 128 - curr_bitvec.length()
            curr_bitvec.pad_from_right(pad_num)

        #Inverse Shift Rows
        block_1 = invShiftrows(curr_bitvec)

        #Inverse Substitute Bytes
        block_2 = invSub_bytes(block_1)

        #Add Round Key
        block_3 = round_keys[14-round_num] ^ block_2

        #Inverse Mix Columns
        if round_num != 14:
            block_3 = invMix_cols(block_3)
        
        #Concatenate the whole block
        total = total + block_3
    
        x += 128
	
    return total
        
def sub_bytes(curr_block): #Substitute Bytes (encryption)
    hex_block = curr_block.get_bitvector_in_hex()
    sub_hex = ""

    #substitute bytes based on the subBytesTable
    for i in range(16):
        j = i * 2
        k = j + 2
        decimal = int(hex_block[j:k], 16)
        sub_ind = subBytesTable[decimal]
        if sub_ind < 16:
            sub_hex += "0" + hex(sub_ind)[2:]
        else:
            sub_hex += hex(sub_ind)[2:]
    return BitVector(hexstring = sub_hex)

def invSub_bytes(curr_block): #Inverse Substitute Bytes (decryption)
    hex_block = curr_block.get_bitvector_in_hex()
    sub_hex = ""

    #substitute bytes based on the invSubBytesTable
    for i in range(16):
        j = i * 2
        k = j + 2
        decimal = int(hex_block[j:k], 16)
        sub_ind = invSubBytesTable[decimal]
        if sub_ind < 16:
            sub_hex += "0" + hex(sub_ind)[2:]
        else:
            sub_hex += hex(sub_ind)[2:]
    return BitVector(hexstring = sub_hex)

def shift_rows(block): #Shift Rows (encryption)
    shift_bv = BitVector(size=128)

    shift_bv = block.deep_copy()

    #row 1
    shift_bv[8:16] = block[40:48]
    shift_bv[40:48] = block[72:80]
    shift_bv[72:80] = block[104:112]
    shift_bv[104:112] = block[8:16]
    #row 2
    shift_bv[16:24] = block[80:88]
    shift_bv[48:56] = block[112:120]
    shift_bv[80:88] = block[16:24]
    shift_bv[112:120] = block[48:56]
    #row 3
    shift_bv[24:32] = block[120:128]
    shift_bv[56:64] = block[24:32]
    shift_bv[88:96] = block[56:64]
    shift_bv[120:128] = block[88:96]
    
    return shift_bv

def invShiftrows(block): #Inverse Shift Rows (decryption)
    shift_bv = BitVector(size=128)

    shift_bv = block.deep_copy()

    #row 1
    shift_bv[8:16] = block[104:112]
    shift_bv[40:48] = block[8:16]
    shift_bv[72:80] = block[40:48]
    shift_bv[104:112] = block[72:80]
    #row 2
    shift_bv[16:24] = block[80:88]
    shift_bv[48:56] = block[112:120]
    shift_bv[80:88] = block[16:24]
    shift_bv[112:120] = block[48:56]
    #row 3
    shift_bv[24:32] = block[56:64]
    shift_bv[56:64] = block[88:96]
    shift_bv[88:96] = block[120:128]
    shift_bv[120:128] = block[24:32]

    return shift_bv

def mix_cols(block): #Mix Columns (encryption)

    mix_done = BitVector(size=0)

    #Coefficient Matrix for encryption
    coef = [[BitVector(intVal=0x2),BitVector(intVal=0x3),BitVector(intVal=0x1),BitVector(intVal=0x1),],
            [BitVector(intVal=0x1),BitVector(intVal=0x2),BitVector(intVal=0x3),BitVector(intVal=0x1),],
            [BitVector(intVal=0x1),BitVector(intVal=0x1),BitVector(intVal=0x2),BitVector(intVal=0x3),],
            [BitVector(intVal=0x3),BitVector(intVal=0x1),BitVector(intVal=0x1),BitVector(intVal=0x2),],]

    #Matrix multiplication with GF and XORing
    for i in range(4):
        mix1 = (block[32*i:32*i+8].gf_multiply_modular(coef[0][0], AES_modulus, 8)) ^ (block[32*i+8:32*i+16].gf_multiply_modular(coef[0][1], AES_modulus, 8)) ^ (block[32*i+16:32*i+24]) ^ (block[32*i+24:32*i+32])
        mix2 = (block[32*i:32*i+8]) ^ (block[32*i+8:32*i+16].gf_multiply_modular(coef[1][1], AES_modulus, 8)) ^ (block[32*i+16:32*i+24].gf_multiply_modular(coef[1][2], AES_modulus, 8)) ^ (block[32*i+24:32*i+32])
        mix3 = (block[32*i:32*i+8]) ^ (block[32*i+8:32*i+16]) ^ (block[32*i+16:32*i+24].gf_multiply_modular(coef[2][2], AES_modulus, 8)) ^ (block[32*i+24:32*i+32].gf_multiply_modular(coef[2][3], AES_modulus, 8))
        mix4 = (block[32*i:32*i+8].gf_multiply_modular(coef[3][0], AES_modulus, 8)) ^ (block[32*i+8:32*i+16]) ^ (block[32*i+16:32*i+24]) ^ (block[32*i+24:32*i+32].gf_multiply_modular(coef[3][3], AES_modulus, 8))
        mix_final = mix1 + mix2 + mix3 + mix4
        mix_done = mix_done + mix_final

    return mix_done

def invMix_cols(block): #Inverse Mix Columns (decryption)

    mix_final = BitVector(size=0)

    #Coefficient Matrix for decryption
    coef = [[BitVector(intVal=0xE),BitVector(intVal=0xB),BitVector(intVal=0xD),BitVector(intVal=0x9),],
            [BitVector(intVal=0x9),BitVector(intVal=0xE),BitVector(intVal=0xB),BitVector(intVal=0xD),],
            [BitVector(intVal=0xD),BitVector(intVal=0x9),BitVector(intVal=0xE),BitVector(intVal=0xB),],
            [BitVector(intVal=0xB),BitVector(intVal=0xD),BitVector(intVal=0x9),BitVector(intVal=0xE),],]

    #Matrix multiplication with GF and XORing
    for i in range(4):
        mix1 = (block[32*i:32*i+8].gf_multiply_modular(coef[0][0], AES_modulus, 8)) ^ (block[32*i+8:32*i+16].gf_multiply_modular(coef[0][1], AES_modulus, 8)) ^ (block[32*i+16:32*i+24].gf_multiply_modular(coef[0][2], AES_modulus, 8)) ^ (block[32*i+24:32*i+32].gf_multiply_modular(coef[0][3], AES_modulus, 8))
        mix2 = (block[32*i:32*i+8].gf_multiply_modular(coef[1][0], AES_modulus, 8)) ^ (block[32*i+8:32*i+16].gf_multiply_modular(coef[1][1], AES_modulus, 8)) ^ (block[32*i+16:32*i+24].gf_multiply_modular(coef[1][2], AES_modulus, 8)) ^ (block[32*i+24:32*i+32].gf_multiply_modular(coef[1][3], AES_modulus, 8))
        mix3 = (block[32*i:32*i+8].gf_multiply_modular(coef[2][0], AES_modulus, 8)) ^ (block[32*i+8:32*i+16].gf_multiply_modular(coef[2][1], AES_modulus, 8)) ^ (block[32*i+16:32*i+24].gf_multiply_modular(coef[2][2], AES_modulus, 8)) ^ (block[32*i+24:32*i+32].gf_multiply_modular(coef[2][3], AES_modulus, 8))
        mix4 = (block[32*i:32*i+8].gf_multiply_modular(coef[3][0], AES_modulus, 8)) ^ (block[32*i+8:32*i+16].gf_multiply_modular(coef[3][1], AES_modulus, 8)) ^ (block[32*i+16:32*i+24].gf_multiply_modular(coef[3][2], AES_modulus, 8)) ^ (block[32*i+24:32*i+32].gf_multiply_modular(coef[3][3], AES_modulus, 8))
        mix_final += mix1 + mix2 + mix3 + mix4

    return mix_final

def AES(bv_input, key):                                            # for decryption
    FILE_KEY = open(key, 'r')
    key = FILE_KEY.read()
    FILE_KEY.close()
    final = BitVector(size=0)

    key_words = []      
    key_schedule = []
    key_bv = BitVector(textstring = key)
    key_words = gen_key_schedule_256(key_bv)
    
    for word_index,word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i*8:i*8+8].intValue())
        key_schedule.append(keyword_in_ints)
    
    num_rounds = 14
    round_keys = [None for i in range(num_rounds+1)]
    for i in range(num_rounds+1):
        round_keys[i] = (key_words[i*4] + key_words[i*4+1] + key_words[i*4+2] + 
                                                       key_words[i*4+3])

    #import argument 1
    '''if sys.argv[1] == str('-e'):
        FILE_PT = open(sys.argv[2])
        pt = FILE_PT.read()
        bv_input = BitVector(textstring = pt)
    elif sys.argv[1] == str('-d'):
        FILE_CT = open(sys.argv[2])
        ct = FILE_CT.read()
        bv_input = BitVector(hexstring = ct)'''
    
    #main function to call encrypt or decrypt for all rounds
    for i in range(15):
        #if sys.argv[1] == str('-e'):
        if i == 0:
            post_round = round_keys_first(bv_input, round_keys)
        elif i == 1:
            curr_block = encrypt(post_round, round_keys, i)
        elif i < 15:
            curr_block = encrypt(curr_block, round_keys, i)
            final = curr_block
            if i == 14:
                #return bitvector     
                return final

def x931(seed, dt, num, key):
    random_nums=[]
    dt_encrypted = AES(dt, key)

    for i in range(num): #call AES
        random_aes = AES(dt_encrypted ^ seed, key)
        random_nums.append(int(random_aes))
        seed = AES(random_aes ^ dt_encrypted, key)

    return random_nums