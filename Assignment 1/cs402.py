"""Some useful Python classes and functions for CS402/MA492 Cryptography.
You can load everything by placing this file somewhere in your Python module
path and running

    from cs402 import *

"""

__date__ = '2019-01-31'

########################################################################
# ALPHABETS
########################################################################

ALPHABET26 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
ALPHABET27 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ "
ALPHABET64 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789. "
ALPHABET68 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,;: \n"
ALPHABET85 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,;:+-/*!?()[]{}_<>'\" \n"
ASCII  = ''.join(chr(i) for i in range(128))
EASCII = ''.join(chr(i) for i in range(256))

########################################################################
# UTILITY FUNCTIONS
########################################################################

def string_to_int_list(alphabet, text):
    try:
        return [alphabet.index(char) for char in text]
    except ValueError:
        raise ValueError('string contains characters not present in given alphabet')

def int_list_to_string(alphabet, int_list):
    try:
        return ''.join(alphabet[i] for i in int_list)
    except IndexError:
        raise ValueError('list of integers contains invalid indices for given alphabet')

def frequency_analysis(text, alphabet=None):
    if alphabet is not None:
        D = {char: 0 for char in alphabet}
    else:
        D = {}

    for char in text:
        D[char] = D.get(char,0) + 1
    return {char: float(count)/len(text) for char,count in D.items()}

def frequency_histogram(text, alphabet=None):
    import matplotlib.pyplot as plt
    D = frequency_analysis(text, alphabet)
    alphabet = sorted(D.keys())
    values = [D[char] for char in alphabet]
    plt.bar(['\\n' if char == '\n' else char for char in alphabet],values)
    plt.show()

########################################################################
# NUMBER THEORY
########################################################################

def gcd(a, b):
    if b < 0:
        a, b = -a, -b
    if b == 0:
        return a
    return gcd(b, a % b)

def egcd(a, b):
    if b < 0:
        x, y = egcd(a, -b)
        return x, -y
    if a < 0:
        x, y = egcd(-a, b)
        return -x, y
    if b == 0:
        return 1, 0
    x, y = egcd(b, a % b)
    return y, x - (a // b) * y

def modular_inverse(a, m):
    x, y = egcd(a,m)
    d = a*x + m*y
    if d != 1:
        raise ValueError('%d is not invertible modulo %d' % (a,m))
    return x % m

def modular_inverse_of_matrix(A, m):
    from sympy import Matrix

    A = Matrix(A)
    det = A.det()
    x = modular_inverse(int(det), m)
    B = x * A.adjugate()
    d,e = A.shape
    return [[int(B[i,j]) % m for j in range(e)] for i in range(d)]

########################################################################
# GENERAL TEXT-BASED CIPHERS
########################################################################

class Cipher:
    def __init__(self, alphabet):
        self.alphabet = alphabet

    # The encryption and decryption function are assumed to act on lists of
    # integers from 0 up to and incluing len(alphabet) - 1.

    def encrypt_int_list(self, key, int_list):
        raise NotImplementedError

    def decrypt_int_list(self, key, int_list):
        raise NotImplementedError

    def encrypt_string(self, key, text):
        return int_list_to_string(self.alphabet,
                                  self.encrypt_int_list(key, string_to_int_list(self.alphabet, text)))

    def decrypt_string(self, key, text):
        return int_list_to_string(self.alphabet,
                                  self.decrypt_int_list(key, string_to_int_list(self.alphabet, text)))

    def encrypt_file(self, key, in_filename, out_filename):
        with open(in_filename, 'r') as in_file:
            text = in_file.read()
        with open(out_filename, 'w') as out_file:
            out_file.write(self.encrypt_string(key, text))

    def decrypt_file(self, key, in_filename, out_filename):
        with open(in_filename, 'r') as in_file:
            text = in_file.read()
        with open(out_filename, 'w') as out_file:
            out_file.write(self.decrypt_string(key, text))

########################################################################
# SHIFT CIPHERS
########################################################################

class ShiftCipher(Cipher):
    def encrypt_int_list(self, key, int_list):
        return [(i + key) % len(self.alphabet) for i in int_list]

    def decrypt_int_list(self, key, int_list):
        return self.encrypt_int_list(-key, int_list)

########################################################################
# AFFINE CIPHERS
########################################################################

class AffineCipher(Cipher):
    def encrypt_int_list(self, key, int_list):
        a,b = key
        if gcd(a, len(self.alphabet)) != 1:
            raise ValueError('invalid key')
        return [(a*i + b) % len(self.alphabet) for i in int_list]

    def decrypt_int_list(self, key, int_list):
        a,b = key
        if gcd(a, len(self.alphabet)) != 1:
            raise ValueError('invalid key')
        x = modular_inverse(a, len(self.alphabet))
        return self.encrypt_int_list([x, (-b*x) % len(self.alphabet)], int_list)

########################################################################
# VIGENERE CIPHERS
########################################################################

class VigenereCipher(Cipher):
    def _process_int_list(self, key, int_list, scalar):
        key_list = string_to_int_list(self.alphabet, key)

        return [(c + scalar * key_list[i % len(key_list)]) % len(self.alphabet) for i,c in enumerate(int_list)]

    def encrypt_int_list(self, key, int_list):
        return self._process_int_list(key, int_list, +1)

    def decrypt_int_list(self, key, int_list):
        return self._process_int_list(key, int_list, -1)

########################################################################
# HIGHER-DIMENSIONAL AFFINE CIPHERS (INCL. HILL CIPHERS)
########################################################################

class HigherAffineCipher(Cipher):
    def __init__(self, alphabet, dimension):
        self.alphabet = alphabet
        self.dimension = dimension

    def encrypt_int_list(self, key, int_list):
        from sympy import Matrix

        m = len(self.alphabet)

        A,b = Matrix(key[0]), Matrix(key[1])
        if len(int_list) % self.dimension:
            raise ValueError('message size is not a multiple of the dimension')

        if gcd(A.det(), m) != 1:
            raise ValueError('invalid key')

        ciphertext = []
        for i in range(len(int_list) // self.dimension):
            x = Matrix(int_list[i*self.dimension:(i+1)*self.dimension])
            y = A * x + b
            ciphertext.extend(int(i) % m for i in y)
        return ciphertext

    def decrypt_int_list(self, key, int_list):
        from sympy import Matrix

        A,b = Matrix(key[0]), Matrix(key[1])
        B = Matrix(modular_inverse_of_matrix(A, len(self.alphabet)))
        return self.encrypt_int_list([B, list(-B*b)], int_list)
