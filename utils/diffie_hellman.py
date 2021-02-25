from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def dh_generate_parameters(key_size=2048):
    parameters = dh.generate_parameters(generator=2, key_size=key_size)
    parameter_numbers = parameters.parameter_numbers()
    p = parameter_numbers.p
    g = parameter_numbers.g

    return [p,g]


def diffie_hellman_generate_public_key(private_key):
    public_key = private_key.public_key()
    public_number_y = public_key.public_numbers().y
    return public_number_y


def diffie_hellman_generate_private_key(parameters):
    p = parameters[0]
    g = parameters[1]
    parameter_numbers = dh.DHParameterNumbers(p, g)
    parameters = parameter_numbers.parameters()

    private_key = parameters.generate_private_key()
    return private_key


def diffie_hellman_common_secret(my_private_key, peer_public_number_y):
    parameters = my_private_key.parameters()
    parameter_numbers = parameters.parameter_numbers()

    peer_public_numbers = dh.DHPublicNumbers(peer_public_number_y, parameter_numbers)
    peer_public_key = peer_public_numbers.public_key()

    shared_key = my_private_key.exchange(peer_public_key)
    derived_key = HKDF(algorithm=hashes.SHA256(),
                       length=32,
                       salt=None,
                       info=b'handshake data').derive(shared_key)
    return derived_key
