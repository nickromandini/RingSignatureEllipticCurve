import logging
import hashlib
import functools
import ecdsa

from ecdsa.ecdsa import curve_secp256k1
from ecdsa.curves import SECP256k1
from ecdsa import numbertheory

from functools import reduce

def verify_ring_signature(message, y, c_0, s, Y, G=SECP256k1.generator):
    """
        Verifies if a valid signature was made by a key inside a set of keys.


        PARAMS
        ------
            message: (str) message whos' signature is being verified.

            y: (list) set of public keys with which the message was signed.

            Signature:
                c_0: (int) initial value to reconstruct the ring.

                s: (list) vector of secrets used to create ring.

                Y = (int) Link of unique signer.

            G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.


        RETURNS
        -------
            Boolean value indicating if signature is valid.

    """
    n = len(y)
    c = [c_0] + [0] * (n - 1)
    H = H2(y)
    for i in range(n):
        z_1 = (G * s[i]) + (y[i] * c[i])
        z_2 = (H * s[i]) + (Y * c[i])

        if i < n - 1:
            c[i + 1] = H1([y, Y, message, z_1, z_2])
        else:
            return c_0 == H1([y, Y, message, z_1, z_2])

    return False


def map_to_curve(x, P=curve_secp256k1.p()):
    """
        Maps an integer to an elliptic curve.


        PARAMS
        ------
            x: (int) number to be mapped into E.

            P: (ecdsa.curves.curve_secp256k1.p) Modulo for elliptic curve.

        RETURNS
        -------
            (ecdsa.ellipticcurve.Point) Point in Curve
    """
    x = x - 1
    found = False

    while not found:
        x = x + 1
        alpha =(((pow(x, 3, P) + (curve_secp256k1.a() * x))) + curve_secp256k1.b()) % P
        try:
            beta = numbertheory.square_root_mod_prime(alpha, P)
            if [beta % 2 == 0] != [x % 2 != 0]:
                y = beta
            else:
                y = P - beta
            found = True
        except Exception as e:
            pass

    return ecdsa.ellipticcurve.Point(curve_secp256k1, x, y)


def H1(msg):
    """
        Return an integer representation of the hash of a message. The
        message can be a list of messages that are concatenated with the
        concat() function.

        PARAMS
        ------
            msg: (str or list) message(s) to be hashed.


        RETURNS
        -------
            Integer representation of hexadecimal digest from hash function.
    """


    return int(hashlib.sha256(concat(msg).encode()).hexdigest(), 16)


def H2(msg):
    """
        Hashes a message into an elliptic curve point.

        PARAMS
        ------
            msg: (str or list) message(s) to be hashed.

        RETURNS
        -------
            ecdsa.ellipticcurve.Point to curve.
    """


    return map_to_curve(H1(msg))


def concat(params):
    """
        Concatenates a list of parameters into a bytes. If one
        of the parameters is a list, calls itself recursively.

        PARAMS
        ------
            params: (list) list of elements, must be of type:
                - int
                - list
                - str
                - ecdsa.ellipticcurve.Point

        RETURNS
        -------
            concatenated bytes of all values.
    """
    n = len(params)
    bytes_value = [0] * n

    for i in range(n):
        if type(params[i]) is int:
            bytes_value[i] = str(params[i])
        if type(params[i]) is list:
            bytes_value[i] = concat(params[i])
        if type(params[i]) is ecdsa.ellipticcurve.Point:
            bytes_value[i] = str(params[i].x()) + str(params[i].y())
        if type(params[i]) is str:
            bytes_value[i] = params[i]
        if bytes_value[i] == 0:
            bytes_value[i] = str(params[i].x()) + str(params[i].y())

    return functools.reduce(lambda x, y: x + y, bytes_value)






import json



with open('keys.json') as f:
    keys = json.load(f)

with open('res.json') as f:
    res = json.load(f)

c_0 = int(res['c_0'])
Y = ecdsa.ellipticcurve.Point(curve_secp256k1, int(res['Y'][0]), int(res['Y'][1]))
s = list(map(int, res['s']))

# eliminate the first two characters, parse in integers and then transform in Points.
keys = [map_to_curve(int(k[2:],16)) for k in keys]

message = "hello"
print(verify_ring_signature(message, keys, c_0, s, Y))