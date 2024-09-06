import secrets
import sys

from secp256r1 import secp256r1
from fastecdsa.encoding.sec1 import SEC1Encoder
from fastecdsa.point import Point
from functools import reduce

from hashlib import sha256

G = secp256r1.G
V = 2 

# Od Tondy
def encode(point: Point) -> bytes:
    return SEC1Encoder.encode_public_key(point, compressed=False)

# Od Tondy
def as_java(b):
    return "{" + ", ".join(map(lambda x: "(byte) " + hex(x), b)) + "}"

def keygen() -> tuple[Point, int]:
    private_key_share = secrets.randbits(256)
    public_key_share = private_key_share * G
    return (public_key_share, private_key_share)

def pubkey_aggregate(keys : list[Point]) -> Point:
    agg_key = G.IDENTITY_ELEMENT
    for key in keys:
        agg_key += key * get_a(keys, key)
    return agg_key

def get_a(keys: list[Point], current_key: Point) -> int:
    sha256_hasher = sha256()
    sha256_hasher.update(SEC1Encoder.encode_public_key(current_key, compressed=False))
    for key in keys:
        sha256_hasher.update(SEC1Encoder.encode_public_key(key, compressed=False))
    return int.from_bytes(sha256_hasher.digest(), byteorder="big")

def gen_nonce() -> tuple[list[Point], list[int]]:
    state_nonce = [secrets.randbits(256) for _ in range(V)]
    out_nonce = [G * state_nonce[i] for i in range(V)]

    return (out_nonce, state_nonce)

def pubnonce_aggregate(nonces : list[list[Point]]) -> list[Point]:
    agg_nonce = [G.IDENTITY_ELEMENT for _ in range(V)]
    for nonce in nonces:
        for i in range(V):
            agg_nonce[i] += nonce[i]
    return agg_nonce

def main():
    print("================")
    print("Musig2 Testing Data")
    print("================")

    participant = {
        "public_key": None,
        "private_key": None,
        "out_nonce": [],
        "state_nonce": []
    }

    if len(sys.argv) != 2:
        no_of_participants = 2
    else:
        no_of_participants = int(sys.argv[1])

    print("private static final int NO_OF_PARTICIPANTS = " + str(no_of_participants) + ";")
    print("private static final int V = " + str(V) + ";")
    print("private static ArrayList<byte[]> privateKeyShares = new ArrayList<>();")
    print("private static ArrayList<byte[]> publicKeyShares = new ArrayList<>();")
    print("private static byte[] aggregatePublicKey = new byte[V];")
    print("private static ArrayList<byte[][]> outNonce = new ArrayList<>();")
    print("private static ArrayList<byte[][]> stateNonce = new ArrayList<>();")
    print("private static ArrayList<byte[]> aggregateOutNonce = new ArrayList<>();")
    print()
    print("@BeforeAll")
    print("public static void setUpClass() throws Exception {")


    participants = [participant] * no_of_participants

    for participant in participants:
        participant["public_key"], participant["private_key"] = keygen()
        participant["out_nonce"], participant["state_nonce"] = gen_nonce()

    aggregate_pubkey = pubkey_aggregate([participant["public_key"] for i in range(no_of_participants)])
    aggregate_nonce = pubnonce_aggregate([participant["out_nonce"] for i in range(no_of_participants)])
    print(f"    aggregatePublicKey = new byte[]{as_java(encode(aggregate_pubkey))};")
    print()

    for nonce in aggregate_nonce:
        print(f"    aggregateOutNonce.add(new byte[]{as_java(encode(nonce))});")

    for participant in participants:
        print()
        state_nonce_java_array = reduce(lambda a, b: "new byte[]" + as_java(a.to_bytes(32, 'big')) + ",\n\t\t\tnew byte[]" + as_java(b.to_bytes(32, 'big')), participant['state_nonce'])
        state_out_java_array = reduce(lambda a, b: "new byte[]" + as_java(encode(a)) + ",\n\t\t\tnew byte[]" + as_java(encode(b)), participant['out_nonce'])
        print(f"    publicKeyShares.add(new byte[]{as_java(encode(participant['public_key']))});")
        print(f"    privateKeyShares.add(new byte[]{as_java((participant['private_key'].to_bytes(32, 'big')))});")
        print("    outNonce.add(new byte[][]{", f"{state_out_java_array}", "});")
        print("    stateNonce.add(new byte[][]{", f"{state_nonce_java_array}", "});")

    print("}")  



if __name__ == "__main__":
    main()