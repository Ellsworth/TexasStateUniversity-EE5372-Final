import ascon

from typing import NamedTuple

import secrets

import secrets
from typing import NamedTuple
import ascon  # Make sure ascon is correctly imported

class AsconMessage(NamedTuple):
    """a docstring"""
    encrypted: bytes
    nonce: bytes
    associated_data: bytes

class AsconClient:
    def __init__(self):
        # Generate a 128-bit (16-byte) random key and initialize nonce
        self.key = secrets.token_bytes(16)
        self.nonce = secrets.token_bytes(16)  # Use a unique 128-bit nonce

    def encrypt(self, message: bytes, associated_data: bytes):
        # Encrypt the message using Ascon
        encrypted = ascon.ascon_encrypt(self.key, self.nonce, associated_data, message)
        
        # Store the current nonce to use in the AsconMessage
        nonce = self.nonce
        
        # Increment the nonce safely (convert to integer, add 1, and convert back)
        self.nonce = (int.from_bytes(self.nonce, byteorder='big') + 1).to_bytes(16, byteorder='big')

        # Return an AsconMessage object with the encrypted message, nonce, and AD
        return AsconMessage(encrypted, nonce, associated_data)

    def decrypt(self, message: AsconMessage):
        # Decrypt using the stored key and the nonce from the AsconMessage
        plaintext = ascon.ascon_decrypt(self.key, message.nonce, message.associated_data, message.encrypted)
        print(plaintext)
        return plaintext, message.associated_data


def main():
    client = AsconClient()

    msg = client.encrypt(bytes([5, 3]), bytes([0xE, 0xA]))
    print(client.decrypt(msg))
    
if __name__ == '__main__':
    main()