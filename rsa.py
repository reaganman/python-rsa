import random
import re
import math
import argparse

alphabet1 = "abcdefghijklmnopqrstuvwxyz"
alphabet2 = ".,?! \t\n\rabcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

def gcd(a, b):
    if b == 0:
        return a
    else:
        return gcd(b, a % b)

class rsa:
    """
    A class implementing the RSA encryption and decryption protocol.

    Args:
    string1 (str): First input string used to generate keys.
    string2 (str): Second input string used to generate keys.
    """
    
    def __init__(self, string1, string2):
        """
        Initializes the RSA object with two input strings -> passphrases to use for key generation.

        Args:
        string1 (str): First input string.
        string2 (str): Second input string.
        """

        self.string1=string1.lower()
        self.string2=string2.lower()

    def to_base_10(self, s, alphabet):
        """
        Converts a string to a base-10 number using the given alphabet.

        Args:
        s (str): Input string to convert.
        alphabet (str): Alphabet used for the conversion.

        Returns:
        int: Base-10 representation of the input string.
        """  

        s = re.sub(rf'[^{alphabet}]', '', s)
        x = 0
        base = len(alphabet)
        for c in s:
            pos = alphabet.find(c)
            x*=base
            x+=pos
        return x

    def from_base_10(self, x, alphabet):
        """
        Converts a base-10 number to a string using the given alphabet.

        Args:
        x (int): Base-10 number to convert.
        alphabet (str): Alphabet used for the conversion.

        Returns:
        str: String representation of the base-10 number.
        """

        base = len(alphabet)
        s = ""
        while x != 0:
            r = x % base
            s += alphabet[r]
            x = x // base
        s = s[::-1]
        return s

    def relatively_prime(self, n):
        """
        Find a number whose only shared factor with n is 1 and is not equal to 1.

        Args:
        n (int): Input number.

        Returns:
        int: A relatively prime number to n.
        """

        r = n - (10**399)
        while gcd(r, n) != 1:
           # r = random.randint(2, n - 1)
           r = r-1
        return r


    def extended_euclidean_algorithm(self, a, b):
        """
        Implements the extended Euclidean algorithm to find the greatest common divisor (gcd),
        and the coefficients x and y satisfying ax + by = gcd(a, b).

        Args:
        a (int): First input number.
        b (int): Second input number.

        Returns:
        Tuple[int, int, int]: GCD and coefficients x, y.
        """

        if a == 0:
            return b, 0, 1
        gcd, x1, y1 = self.extended_euclidean_algorithm(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd, x, y

    def find_modular_inverse(self, a, m):
        """
        Finds the modular inverse of a modulo m.

        Args:
        a (int): Input number.
        m (int): Modulus.

        Returns:
        int: Modular inverse of a modulo m.
        """
        
        gcd, x, y = self.extended_euclidean_algorithm(a, m)
        if gcd != 1:
            raise ValueError("The modular inverse does not exist.")
        elif x<m:
            return x+m
        else:
            return x%m

    def millers_test(self, n, b):
        """
        Performs the Miller-Rabin primality test.

        Args:
        n (int): Input number to test for primality.
        b (int): Randomly chosen base for the test.

        Returns:
        bool: True if n is likely to be prime, False otherwise.
        """

        #  Find s and t where n-1=2^s*t
        s, t = 0, n - 1
        while t % 2 == 0:
            s, t = s + 1, t // 2

        if pow(b, t, n) == 1:
            return True

        for j in range(s):
            if pow(b, 2**j * t, n) == n - 1:
                return True
        return False

    def is_prime_miller(self, n):
        """
        Uses the Miller-Rabin test to check if a number is likely to be prime.

        Args:
        n (int): Input number.

        Returns:
        bool: True if n is likely to be prime, False otherwise.
        """

        if n == 1 or n == 2:
            return True
        for i in range(50):
            b = random.randint(2, n - 1)
            if not self.millers_test(n, b):
                return False
        return True

    def generate_keys(self):
        """
        Generates RSA public and private keys (200 digit prime numbers) from provided keyphrases and saves them to 'public.txt' and 'private.txt' files.
        """

        p = self.to_base_10(self.string1, alphabet1)
        q = self.to_base_10(self.string2, alphabet1)
        # check size
        if p < 10**200:
            print("Warning! p to small!")
        if q < 10**200:
            print("Warning! q to small!")
        #make p and q right size
        p = p % (10**200)
        q = q % (10**200)
        #make em odd
        if p%2==0:
            p+=1
        if q%2==0:
            q+=1
        #add 2 till prime
        while not self.is_prime_miller(p):
            p+=2
        while not self.is_prime_miller(q):
            q+=2

        #calculate n, r, e , d
        n=p*q
        r=(p-1)*(q-1)
        e=self.relatively_prime(r)
        d=self.find_modular_inverse(e,r)

        if (e*d)%r==1:

            with open('public.txt','w') as pub_out:
                pub_out.write(f'{n}\n{e}')
            with open('private.txt','w') as priv_out:
                priv_out.write(f'{n}\n{d}')
        else:
            raise ValueError(f"({e} * {d}) % {r} !=1")

    def encrypt(self, infile, outfile):
        """
        Encrypts the contents of the input file and saves the result to the output file.

        Args:
        infile (str): Path to the file to be encrypted.
        outfile (str): Path to save the encrypted file.
        """

        with open('public.txt', 'r') as pub:
            n = int(pub.readline())
            e = int(pub.readline())
        fin = open(infile, 'rb')
        PT_binary = fin.read()
        PT = PT_binary.decode('utf-8')
        fin.close()

        #initilazie block structure
        max_bytes_per_block = (math.log(n,70))
        ptl = len(PT)
        blocks_needed = math.ceil(ptl/max_bytes_per_block)
        bytes_per_block = ptl//blocks_needed

        #loop through block and encode
        EC_blocks = []
        for i in range(blocks_needed):
            #check if last block
            if i == (blocks_needed-1):
                PT_block = PT[i*bytes_per_block:]
            else:
                PT_block = PT[i*bytes_per_block:(i+1)*bytes_per_block]

            PN_block = self.to_base_10(PT_block, alphabet2)
            EN_block = pow(PN_block, e, n)
            ET_block = self.from_base_10(EN_block, alphabet2)
            ET_block += '$'
            EC_blocks.append(ET_block)

        #write to outfile
        fout = open(outfile, 'wb')
        for block in EC_blocks:
            fout.write(block.encode('utf-8'))
        fout.close()


    def decrypt(self, infile, outfile):
        """
        Decrypts the contents of the input file and saves the result to the output file.

        Args:
        infile (str): Path to the encrypted file.
        outfile (str): Path to save the decrypted file.
        """

        #get n and d
        with open('private.txt', 'r') as priv:
            n = int(priv.readline())
            d = int(priv.readline())

        #get encrypted blocks
        fin = open(infile, 'rb')
        ET_binary = fin.read()
        ET = ET_binary.decode('utf-8')
        fin.close()
        ET_blocks = ET.split('$')[:-1]

        #decrypt blocks
        DT_blocks = []
        for block in ET_blocks:
            EN_block = self.to_base_10(block, alphabet2)
            DN_block = pow(EN_block, d, n)
            DT_block = self.from_base_10(DN_block, alphabet2)
            DT_blocks.append(DT_block)

        #write to outfile
        fout = open(outfile, 'wb')
        for block in DT_blocks:
            fout.write(block.encode('utf-8'))
        fout.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A script for generating RSA key pairs and encrypting and decrypting according to the RSA protocol")

    parser.add_argument('key_phrase', help='Path to a text file with two lines -> keyphrases to generate public and private keys')
    parser.add_argument('--keygen', '-kg', action='store_true', help='Flag to generate public and private keys')
    parser.add_argument('--encrypt', '-e', help='Path to a file to encrypt')
    parser.add_argument('--decrypt', '-d', help='Path to an encrypted file to decrypt')

    args = parser.parse_args()

    with open(args.key_phrase, 'r') as key_phrase:
        string1 = key_phrase.readline().strip()
        string2 = key_phrase.readline().strip()

    rsa_obj = rsa(string1, string2)

    if args.keygen:
        rsa_obj.generate_keys()

    if args.encrypt:
        fout = args.encrypt.rsplit('.')[0] + "_encrypted.txt"
        rsa_obj.encrypt(args.encrypt, fout)
        print(f"Encrypted file saved to {fout}")

    if args.decrypt:
        fout = args.decrypt.rsplit('.')[0] + "_decrypted.txt"
        rsa_obj.decrypt(args.decrypt, fout)
        print(f"Decrypted file saved to {fout}")
