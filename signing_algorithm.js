
const ecurve = require('ecurve') // used to work with elliptic curve
const BigInteger = require('bigi')
const sjcl = require('sjcl')
const crypto = require('crypto')
const curve256k1 = ecurve.getCurveByName('secp256k1')

// method used when input parameters are HEX values 
const ring_signature_hex = (signing_key, key_idx, M, y) => {

    signing_key_int = new BigInteger(signing_key,16) // converting private key from HEX to BigInteger
    pubkeys_as_points = []
    // converting public keys in Point on the curve
    for(var i = 0 ; i<y.length; i++) {
        temp = new BigInteger(y[i].slice(2), 16) // remove the first two digit
        pubkeys_as_points[i] = curve256k1.pointFromX(!temp.isEven(),temp)
    }

    signature = ring_signature(signing_key_int, key_idx, M, pubkeys_as_points)
    result = []
    result[0] = signature[0].toString()
    result[1] = signature[2].affineX.toString()
    result[2] = signature[2].affineY.toString()
    for(var i = 0; i < signature[1].length; i++) {
        result[i + 3] = signature[1][i].toString()
    }
    return result
}

// method used when input parameters are already converted
const ring_signature = (signing_key, key_idx, M, y) => {
    /*
        Generates a ring signature for a message given a specific set of
        public keys and a signing key belonging to one of the public keys
        in the set.

        PARAMS
        ------

            signing_key: (int) The with which the message is to be anonymously signed.

            key_idx: (int) The index of the public key corresponding to the signature
                private key over the list of public keys that compromise the signature.

            M: (str) Message to be signed.

            y: (list) The list of public keys which over which the anonymous signature
                will be compose.

            G: (ecdsa.ellipticcurve.Point) Base point for the elliptic curve.


        RETURNS
        -------

            Signature (c_0, s, Y) :
                c_0: Initial value to reconstruct signature.
                s = vector of randomly generated values with encrypted secret to 
                    reconstruct signature.
                Y = Link for current signer.

    */
    G=curve256k1.G
    nkeys = y.length
    c = new Array(nkeys)
    s = new Array(nkeys)

    // STEP 1
    H = H2(y)

    // creating link for current signer. Y is a Point on the curve
    Y =  H.multiply(signing_key)

    // STEP 2

    u = new BigInteger(crypto.randomBytes(32).toString("hex"),16)

    c[(key_idx + 1) % nkeys] = H1([y, Y, M, G.multiply(u), H.multiply(u)])

    // STEP 3
    for (var i = (key_idx+1)%nkeys; i != key_idx; i=(i+1)%nkeys) {
        s[i] = new BigInteger(crypto.randomBytes(32).toString("hex"), 16)
        z_1 = (G.multiply(s[i])).add(y[i].multiply(c[i]))
        z_2 = (H.multiply(s[i])).add(Y.multiply(c[i]))
        c[(i + 1) % nkeys] = H1([y, Y, M, z_1, z_2])
    }
    // STEP 4
    s[key_idx] = (u.subtract(signing_key.multiply(c[key_idx]))).mod(new BigInteger("" + curve256k1.n))

    return [c[0], s, Y]
}

const H1 = (msg) =>{
    return new BigInteger(sjcl.codec.hex.fromBits(sjcl.hash.sha256.hash(concat(msg))),16)
}

const H2 = (msg) => {
    var a = H1(msg)
    return map_to_curve(a)
}

// implementation of try-and-increment algorithm
const map_to_curve = (x) =>{
    x = x.subtract(BigInteger.ONE)
    found = false
    while(!found) {
        x = x.add(BigInteger.ONE)
        p = curve256k1.pointFromX(!x.isEven(),x)
        if(curve256k1.isOnCurve(p)) {
            found = true
        }
    }
    return p
}

// create a single string composed by values in params
const concat = (params) => {

    len = params.length
    bytes_value = new Array(len)


    for (i = 0; i < len; i++) {
        if(typeof params[i] == 'string') {
            bytes_value[i] = params[i]
        } else if(params[i] instanceof Array) {
            l = params[i].length
            temp = new Array(l)
            for (k= 0; k < l; k++) {
                temp[k] = "" + params[i][k].affineX.toString() + params[i][k].affineY.toString()
            }
            bytes_value[i] = temp.join('')
        } else {
            bytes_value[i] = "" + params[i].affineX.toString() + params[i].affineY.toString()
        }

    }

    return bytes_value.join('')


}


module.exports = {
    ring_signature_hex
}






