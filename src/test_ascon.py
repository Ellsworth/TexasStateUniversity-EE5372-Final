import ascon

from typing import NamedTuple

import secrets

#import secrets
#from typing import NamedTuple
#import ascon  # Make sure ascon is correctly imported

class AsconMessage(NamedTuple):
    """
    encrypted: bytes - the encrypted message.
    nonce: bytes - a shared public token that should never be reused.
    associated_data: bytes - authenticated data. not encrypted. useful for sharing sender and receiver.
    """
    encrypted: bytes
    nonce: bytes
    associated_data: bytes

class AsconClient:
    def __init__(self):
        # Generate a 128-bit (16-byte) random key and initialize nonce
        self.key = secrets.token_bytes(16)
        self.nonce = secrets.token_bytes(16)  # Use a unique 128-bit nonce

    def encrypt(self, message: bytes, associated_data: bytes) -> AsconMessage:
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

        return plaintext, message.associated_data

#Class node inherits from AsconClient
class Node(AsconClient):
    def __init__(self, ID, key=None):
        super().__init__()
        self.ID = ID

        if key:
            self.key = key

    def send_message(self, recipient, message: bytes, associated_data: bytes):
        """
        Sends the encrypted data to the chosen recipient.
        """
        print(f"Node {self.ID} sending message to Node {recipient.ID}")
        encrypted_message = self.encrypt(message, associated_data)
        recipient.receive_message(encrypted_message)

    def receive_message(self, encrypted_message: AsconMessage):
        """
        Receives the encrypted message and attempts to decrypt it.
        """
        print(f"Node {self.ID} received a message...")

        try:
            #decrypt the message
            descrypted_message = self.decrypt(encrypted_message)
            print(f"Node {self.ID} decrypted the message: {descrypted_message}")
        except ValueError as e:
            print(f"Node {self.ID} failed to decrypt the message: {e}")

#Class Server inherits from Node
class Server:
    def __init__(self):
        self.node_keys = {}
        self.nodes = {}
        self.messages = {}

    # Registers node in the node and keys dict
    def register_node(self, node):
        # Store the node's key and instance
        self.node_keys[node.ID] = node.key
        self.nodes[node.ID] = node
        print(f"Server registered Node {node.ID} with a unique key")
        
    def send_message(self, sender_id, recipient_id, message, associated_data):
        print(f"\nServer: Node {sender_id} wants to send a message to Node {recipient_id}")
        sender_node = self.nodes[sender_id]
        recipient_node = self.nodes[recipient_id]

        # Sender encrypts the message using their key
        encrypted_message = sender_node.encrypt(message, associated_data)

        # Server decrypts the message using sender's key
        plaintext, _ = self.server_decrypt(sender_id, encrypted_message)

        # Server re-encrypts the message using recipient's key
        new_encrypted_message = self.server_encrypt(recipient_id, plaintext, associated_data)

        # Store the message for possible interception
        self.messages[recipient_id] = new_encrypted_message

        # Server sends the encrypted message to the recipient
        recipient_node.receive_message(new_encrypted_message)

    def server_decrypt(self, node_id, encrypted_message):
        key = self.node_keys[node_id]
        nonce = encrypted_message.nonce
        associated_data = encrypted_message.associated_data
        encrypted = encrypted_message.encrypted
        plaintext = ascon.ascon_decrypt(key, nonce, associated_data, encrypted)
        return plaintext, associated_data

    def server_encrypt(self, node_id, message, associated_data):
        key = self.node_keys[node_id]
        # Generate a new nonce
        nonce = secrets.token_bytes(16)
        encrypted = ascon.ascon_encrypt(key, nonce, associated_data, message)
        return AsconMessage(encrypted=encrypted, nonce=nonce, associated_data=associated_data)

    def get_message_for_node(self, node_id):
        return self.messages.get(node_id, None)


def experiment1():
    """
    Initialize nodes, assign the same key to the nodes.
    Then simulate the nodes talking to each other.
    Then 
    """

    print("=== Experiment 1: Shared Key Across All Nodes ===")
    # Generate the key that will be used across all the nodes
    sameKey = secrets.token_bytes(16)

    # List of nodes
    nodes = []

    # Initialize X amount of nodes for the experiment. 
    for i in range(1,6):
        node = Node(ID=i, key=sameKey) #Same key assigned to every node
        nodes.append(node)
        print(f"Created node {node.ID}")


    # Simulate communication between nodes
    # Node 1 sends a message to Node 3
    message = b"Some data from Node 1 to Node 3"
    associated_data = b"Experiment1"
    nodes[0].send_message(nodes[2], message, associated_data)

    # Node 2 sends a message to Node 5
    message = b"Sensitive data from Node 2 to Node 5"
    nodes[1].send_message(nodes[4], message, associated_data)

    # Node 4 intercepts the message sent from Node 2 to Node 5
    # Node 4 is capable of doing that since all nodes share the same key
    print("\nNode 4 intercepts the message sent from Node 2 to Node 5")
    # For the simulation of interception, we'll assume that Node 4 receives the same encrypted message (Node 4 is on the path from Node 2 to Node 5)
    intercepted_message = nodes[1].encrypt(message, associated_data)
    nodes[3].receive_message(intercepted_message)


    


def experiment2():
    """
    Initialize nodes with unique keys. Store them on a server
    Simulate nodes communicating via the server
    """

    print("\n\n\n=== Experiment 2: Unique Keys with Central Server ===")

    server = Server()

    nodes = []

    # Initialize X amount of nodes for the experiment. 
    for i in range(1,6):
        node = Node(ID=i) #Same key assigned to every node
        nodes.append(node)
        print(f"Created node {node.ID}")
        # Register the node with the server
        server.register_node(node)

    # Node 1 sends a message to Node 3
    message = b"Data from Node 1 to Node 3"
    associated_data = b"Experiment2"
    server.send_message(sender_id=1, recipient_id=3, message=message, associated_data=associated_data)

    message = b"Sensitive data from Node 2 to Node 5"
    server.send_message(sender_id = 2, recipient_id=5, message=message, associated_data=associated_data)

    print("\nNode 4 attemts to intercept the message sent from Node 2 to Node 5")
    intercepted_message = server.get_message_for_node(5)
    if intercepted_message:
        nodes[3].receive_message(intercepted_message)
    else:
        print("No message found for node 5")



def main():
    experiment1()
    experiment2()
    
if __name__ == '__main__':
    main()