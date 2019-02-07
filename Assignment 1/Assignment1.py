# Student ID: 15315901
#CS402 Assignment 1

# Import cs402 py file
from cs402 import *

# Reading data from files
q2_file = open('a1q2-cipher7.txt', 'r')
q2_decrypt = open('a1q2-cipher7-decrypt.txt', 'w')
q2_str = 'Gulliver'

q3_file = open('a1q3-cipher8.txt', 'r')
q3_decrypt = open('a1q3-cipher8-decrypt.txt', 'w')
q3_str = 'mathematical'

q4_file = open('a1q4-cipher8.txt', 'r')

q2_alpha = ShiftCipher(ALPHABET68)
print(ALPHABET68)

print(ALPHABET68.index(' '))

print(ALPHABET68.index('3'))

#q2_freq = frequency_histogram(q2_file.read(), ALPHABET68)
'''
(X + K) mod n = e
(66 + 57) % 68 = 55

so:
X = 66 = ' ' (spacebar)
    This is our original, unencrypted value that shows up. This is calculated by
generating a frequency historgram, and knowledge that the  most common character
that could show up in a file. It is the 67th character in the list

k = 57
    This is our key. It indicates the amount of characters the alphabet (in this case ALPHABET68)
is shifted to the right by. For example, a is the first character in ALPHABET68, its indice is 0.
with k = 57, the alphabet would have a as being the 56th character.

n = 68
    This is the length of our alphabet.

e = 55 = '3'
    This is the encrypted value of X after the shift is employed. In other words,
any ' ' (spaces) in a text, encryped under k=57, would read as '3' instead.


Short answer is our key is 57
'''

q2_alpha.decrypt_file(57, 'a1q2-cipher7.txt', 'a1q2-cipher7-decrypt.txt')

# Gulliver = vjaa:k9g
print( q2_alpha.encrypt_string(57, 'Gulliver'))

print(ALPHABET68.index('G'))

print(ALPHABET68.index('v'))
