# Copyright is waived. No warranty is provided. Unrestricted use and modification is permitted.

import os
import sys
import re
import base64
import socket

PURPOSE = """\
Print SSH 2.0 host key

ssh2-host-key.py <ip_address>

Implements just enough of RFC5246 to get the job done; see here for details;
https://www.ssh.com/ssh/protocol/#sec-IETF-SSH-standard-and-detailed-technical-documentation
"""


class Stream:

    LITTLE_ENDIAN = 0
    BIG_ENDIAN = 1

    def __init__(self):
        self.length = 0
        self.endian = self.LITTLE_ENDIAN

    def get_length(self):
        return self.length

    def set_endian(self, value):
        self.endian = value

    def write_byte(self, value):
        raise ("Virtual function")

    def write_bytes(self, data):
        raise ("Virtual function")

    def write_bool(self, value):
        bool_byte = 1 if value else 0
        self.write_byte(bool_byte)

    def write_short(self, value):
        if self.endian == self.LITTLE_ENDIAN:
            self.write_byte(value & 0xff)
            self.write_byte(value >> 8)
        else:
            self.write_byte(value >> 8)
            self.write_byte(value & 0xff)

    def write_int(self, value):
        if self.endian == self.LITTLE_ENDIAN:
            self.write_short(value & 0xffff)
            self.write_short(value >> 16)
        else:
            self.write_short(value >> 16)
            self.write_short(value & 0xffff)

    def write_string(self, string):
        string_data = string.encode("latin_1")
        self.write_bytes(string_data)

    def write_name_list(self, names):
        string = ",".join(names)
        self.write_int(len(string))
        self.write_string(string)

    def read_byte(self):
        raise ("Virtual function")

    def read_bytes(self, length):
        raise ("Virtual function")

    def read_bool(self):
        value = self.read_byte()
        return False if value == 0 else True

    def read_short(self):
        if self.endian == self.LITTLE_ENDIAN:
            value = self.read_byte() + (self.read_byte() << 8)
        else:
            value = (self.read_byte() << 8) + self.read_byte()
        return value

    def read_int(self):
        if self.endian == self.LITTLE_ENDIAN:
            value = self.read_short() + (self.read_short() << 16)
        else:
            value = (self.read_short() << 16) + self.read_short()
        return value

    def read_string(self, length):
        value = self.read_bytes(length)
        return value.decode("latin_1")

    # CR/LF terminated string; CR/LF is returned with string
    def read_crlf_string(self):
        output = bytearray()
        value = self.read_byte()
        while value != 0x0d:
            output.append(value)
            value = self.read_byte()
        output.append(value)
        output.append(self.read_byte())      # Expected to be 0x0a (line feed)
        return output.decode("latin_1")

    def read_name_list(self):
        string_length = self.read_int()
        names = self.read_string(string_length)
        return names.split(",")


class ByteStream(Stream):

    def __init__(self):
        Stream.__init__(self)
        self.data = bytearray()
        self.position = 0

    def set_data(self, data, length=None):
        self.data = bytearray(data)
        if length is None:
            self.length = len(self.data)
        else:
            self.length = length
        self.position = 0

    def get_data(self):
        return self.data

    def write_byte(self, value):
        self.data.append(value)
        self.length += 1

    def write_bytes(self, data):
        self.data += data
        self.length += len(data)

    def read_byte(self):
        value = self.data[self.position]
        self.position += 1
        return value

    def read_bytes(self, length):
        value = self.data[self.position:self.position + length]
        self.position += length
        return value


class SocketStream(Stream):

    def __init__(self, socket):
        Stream.__init__(self)
        self.socket = socket
        self.write_buffer = bytearray()
        self.read_buffer = bytearray()
        self.read_buffer_length = 0
        self.read_position = 0

    def close(self):
        self.socket.close()

    def read_seek(self, offset):
        if self.read_position + offset < 0:
            raise ValueError("Stream underflow")
        self.read_position += offset

    def read_byte(self):
        return self.read_bytes(1)[0]

    def read_bytes(self, length):
        if self.read_position + length > len(self.read_buffer):
            # Read enough to satisfy request plus some extra for read ahead caching
            self.read_buffer = self.read_buffer[self.read_position:] + self.socket.recv(length + 16384)
            self.read_position = 0
        data = self.read_buffer[self.read_position:self.read_position + length]
        self.read_position += length
        return data

    def write_byte(self, value):
        self.write_buffer.append(value)
        self.length += 1

    def write_bytes(self, data):
        self.write_buffer += data
        self.length += len(data)

    def flush(self):
        self.socket.sendall(self.write_buffer)
        self.write_buffer = bytearray()
        self.length = 0


# SSH Messages
SSH_MSG_KEXINIT = 20
SSH_MSG_KEX_ECDH_INIT = 30
SSH_MSG_KEX_ECDH_REPLY = 31

# Algorithms supported in this implementation
KEX_ALGORITHMS = ["curve25519-sha256"]
HOST_KEY_ALGORITHMS = ["ecdsa-sha2-nistp256"]
ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER = ["aes128-ctr"]
ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT = ["aes128-ctr"]
MAC_ALGORITHMS_CLIENT_TO_SERVER = ["hmac-sha1"]
MAC_ALGORITHMS_SERVER_TO_CLIENT = ["hmac-sha1"]
COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER = ["none"]
COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT = ["none"]


class SSH_Message:
    def __init__(self):
        self.payload = None
        self.message = ByteStream()
        self.message.set_endian(ByteStream.BIG_ENDIAN)

    def read(self, stream):
        packet_length = stream.read_int()
        padding_length = stream.read_byte()
        payload_length = packet_length - padding_length - 1
        self.payload = stream.read_bytes(payload_length)
        stream.read_seek(padding_length)
        self.message.set_data(self.payload)

    def write(self, stream):
        block_size = 8
        payload_length = len(self.payload)
        padding_length = block_size - ((payload_length+5) & (block_size-1))
        if padding_length < 4:
            padding_length += block_size
        stream.write_int(payload_length + padding_length + 1)
        stream.write_byte(padding_length)
        stream.write_bytes(self.payload)
        stream.write_bytes(os.urandom(padding_length))
        stream.flush()


class KEXINIT_Message(SSH_Message):

    def __init__(self):
        SSH_Message.__init__(self)
        self.cookie = None
        self.kex_algorithms = None
        self.host_key_algorithms = None
        self.encryption_algorithms_client_to_server = None
        self.encryption_algorithms_server_to_client = None
        self.mac_algorithms_client_to_server = None
        self.mac_algorithms_server_to_client = None
        self.compression_algorithms_client_to_server = None
        self.compression_algorithms_server_to_client = None
        self.languages_client_to_server = []
        self.languages_server_to_client = []
        self.first_kex_packet_follows = False

    def read(self, stream):
        SSH_Message.read(self, stream)
        message_type = self.message.read_byte()
        if message_type != SSH_MSG_KEXINIT:
            sys.exit("Unexpected message type")
        self.cookie = self.message.read_bytes(16)
        self.kex_algorithms = self.message.read_name_list()
        self.host_key_algorithms = self.message.read_name_list()
        self.encryption_algorithms_client_to_server = self.message.read_name_list()
        self.encryption_algorithms_server_to_client = self.message.read_name_list()
        self.mac_algorithms_client_to_server = self.message.read_name_list()
        self.mac_algorithms_server_to_client = self.message.read_name_list()
        self.compression_algorithms_client_to_server = self.message.read_name_list()
        self.compression_algorithms_server_to_client = self.message.read_name_list()
        self.languages_client_to_server = self.message.read_name_list()
        self.languages_server_to_client = self.message.read_name_list()
        self.first_kex_packet_follows = self.message.read_bool()
        reserved = self.message.read_int()

    def write(self, stream):
        self.cookie = os.urandom(16)
        self.message.write_byte(SSH_MSG_KEXINIT)
        self.message.write_bytes(self.cookie)
        self.message.write_name_list(KEX_ALGORITHMS)
        self.message.write_name_list(HOST_KEY_ALGORITHMS)
        self.message.write_name_list(ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER)
        self.message.write_name_list(ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT)
        self.message.write_name_list(MAC_ALGORITHMS_CLIENT_TO_SERVER)
        self.message.write_name_list(MAC_ALGORITHMS_SERVER_TO_CLIENT)
        self.message.write_name_list(COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER)
        self.message.write_name_list(COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT)
        self.message.write_name_list(COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER)
        self.message.write_name_list(COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT)
        self.message.write_bool(False)        # first_kex_packet_follows
        self.message.write_int(0)             # reserved
        self.payload = self.message.get_data()
        SSH_Message.write(self, stream)


class KEX_ECDH_INIT_Message(SSH_Message):
    def __init__(self):
        SSH_Message.__init__(self)
        self.key_data = None

    def read(self, stream):
        SSH_Message.read(self, stream)
        message_type = self.message.read_byte()
        if message_type != SSH_MSG_KEX_ECDH_INIT:
            sys.exit("Unexpected message type")
        key_length = self.message.read_int()
        self.key_data = self.message.read_bytes(key_length)

    def write(self, stream):
        self.message.write_byte(SSH_MSG_KEX_ECDH_INIT)
        self.message.write_int(32)
        self.message.write_bytes(os.urandom(32))
        self.payload = self.message.get_data()
        SSH_Message.write(self, stream)


class KEX_ECDH_REPLY_Message(SSH_Message):
    def __init__(self):
        SSH_Message.__init__(self)
        self.host_key_b64 = None

    def read(self, stream):
        SSH_Message.read(self, stream)
        message_type = self.message.read_byte()
        if message_type != SSH_MSG_KEX_ECDH_REPLY:
            sys.exit("Unexpected message type")
        host_length = self.message.read_int()
        host_key = self.message.read_bytes(host_length)
        self.host_key_b64 = base64.b64encode(host_key)
        server_value_length = self.message.read_int()
        server_value_data = self.message.read_bytes(server_value_length)
        signature_length = self.message.read_int()
        signature = self.message.read_bytes(signature_length)


class SSHSocket:

    def __init__(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.stream = None
        self.remote_identifier = None
        self.remote_kexinit = None
        self.read_sequence_id = 0
        self.write_sequence_id = 0
        self.host_key_b64 = None

    def listen(self):
        self.socket.bind(("127.0.0.1", 22))
        self.socket.listen(1)
        incoming_socket, address = self.socket.accept()
        self.stream = SocketStream(incoming_socket)
        self.stream.set_endian(SocketStream.BIG_ENDIAN)

        # Receive remote identifier
        self.remote_identifier = self.__receive_identifier()

        # Send local identifier
        self.stream.write_string(b"SSH-2.0-FRANKIE\r\n")
        self.stream.flush()

        # Receive remote key exchange initialization
        self.remote_kexinit = KEXINIT_Message()
        self.remote_kexinit.read(self.stream)
        self.read_sequence_id += 1

        # Send key exchange initialization
        local_kexinit = KEXINIT_Message()
        local_kexinit.write(self.stream)
        self.write_sequence_id += 1

        # Identify matching algorithms
        kex_algorithm = None
        for algorithm in self.remote_kexinit.kex_algorithms:
            if algorithm in KEX_ALGORITHMS:
                kex_algorithm = algorithm
                break
        if not kex_algorithm:
            sys.exit("Unable to find matching key exchange algorithm")

        host_key_algorithm = None
        for algorithm in self.remote_kexinit.host_key_algorithms:
            if algorithm in HOST_KEY_ALGORITHMS:
                host_key_algorithm = algorithm
                break
        if not host_key_algorithm:
            sys.exit("Unable to find matching host key algorithm")

        client_server_cipher = None
        for algorithm in self.remote_kexinit.encryption_algorithms_client_to_server:
            if algorithm in ENCRYPTION_ALGORITHMS_CLIENT_TO_SERVER:
                client_server_cipher = algorithm
                break
        if not client_server_cipher:
            sys.exit("Unable to find matching client to server cipher")

        client_server_mac = None
        for algorithm in self.remote_kexinit.mac_algorithms_client_to_server:
            if algorithm in MAC_ALGORITHMS_CLIENT_TO_SERVER:
                client_server_mac = algorithm
                break
        if not client_server_mac:
            sys.exit("Unable to find matching client to server MAC algorithm")

        client_server_compression = None
        for algorithm in self.remote_kexinit.compression_algorithms_client_to_server:
            if algorithm in COMPRESSION_ALGORITHMS_CLIENT_TO_SERVER:
                client_server_compression = algorithm
                break
        if not client_server_compression:
            sys.exit("Unable to find matching client to server compression algorithm")

        server_client_cipher = None
        for algorithm in self.remote_kexinit.encryption_algorithms_server_to_client:
            if algorithm in ENCRYPTION_ALGORITHMS_SERVER_TO_CLIENT:
                server_client_cipher = algorithm
                break
        if not server_client_cipher:
            sys.exit("Unable to find matching server to client cipher")

        server_client_mac = None
        for algorithm in self.remote_kexinit.mac_algorithms_server_to_client:
            if algorithm in MAC_ALGORITHMS_SERVER_TO_CLIENT:
                server_client_mac = algorithm
                break
        if not server_client_mac:
            sys.exit("Unable to find matching server to client MAC algorithm")

        server_client_compression = None
        for algorithm in self.remote_kexinit.compression_algorithms_server_to_client:
            if algorithm in COMPRESSION_ALGORITHMS_SERVER_TO_CLIENT:
                server_client_compression = algorithm
                break
        if not server_client_compression:
            sys.exit("Unable to find matching server to client compression algorithm")

        # Perform remote key exchange
        kex_init = KEX_ECDH_INIT_Message()
        kex_init.read(self.stream)

    def connect(self, address):
        self.socket.connect(address)
        self.stream = SocketStream(self.socket)
        self.stream.set_endian(SocketStream.BIG_ENDIAN)

        # Send local identifier
        self.stream.write_bytes(b"SSH-2.0-FRANKIE\r\n")
        self.stream.flush()

        # Receive remote identifier
        self.remote_identifier = self.__receive_identifier()

        # Send local key exchange initialization
        local_kexinit = KEXINIT_Message()
        local_kexinit.write(self.stream)
        self.write_sequence_id += 1

        # Receive remote key exchange initialization
        self.remote_kexinit = KEXINIT_Message()
        self.remote_kexinit.read(self.stream)
        self.read_sequence_id += 1

        # Perform remote key exchange
        kex_init = KEX_ECDH_INIT_Message()
        kex_init.write(self.stream)

        kex_reply = KEX_ECDH_REPLY_Message()
        kex_reply.read(self.stream)
        self.host_key_b64 = kex_reply.host_key_b64

    def get_ecdsa_host_key(self):
        return self.host_key_b64

    def send(self, message):
        pass

    def recv(self):
        pass

    def close(self):
        self.socket.close()

    def __receive_identifier(self):
        # The identifier can be preceded by a text banner; limit this to prevent attack
        for i in range(9):
            line = self.stream.read_crlf_string()
            if re.search("^SSH-2.0-", line):
                return line.split()[0]
        sys.exit("Maximum banner size exceeded")


if __name__ == '__main__':

    if len(sys.argv) < 2:
        sys.exit(PURPOSE)

    if sys.version_info < (3, 6):
        sys.exit("Requires Python 3.6 or later")

    ip_address = sys.argv[1]
    ssh = SSHSocket()
    ssh.connect((ip_address, 22))
    fingerprint = ssh.get_ecdsa_host_key().decode("latin_1")
    ssh.close()
    print(fingerprint)
