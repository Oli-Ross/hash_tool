from base64 import urlsafe_b64encode, b64encode, b32encode, b85encode
import argparse
import binascii
import hashlib
from typing import Dict, Optional, Tuple, List

hash_funcs = {
    name: getattr(hashlib, name)
    for name in hashlib.algorithms_available
    if hasattr(hashlib, name)
}

encode_funcs = {
    "base64": b64encode,
    "base85": b85encode,
    "base32": b32encode,
    "base64url": urlsafe_b64encode,
    "hex": binascii.hexlify,
}

pre_transforms = {
    "": lambda x: x,
    "strip": str.strip,
    "leadingspace": lambda x: " " + x,
    "trailingspace": lambda x: x + " ",
}

transforms = {
    "": lambda x: x,
    "capital": str.capitalize,
    "lower": str.lower,
    "upper": str.upper,
}

post_transforms = {
    "quote": lambda x: '"' + x + '"',
    "": lambda x: x,
}


def hash(sentinels_transformed: Dict) -> Dict:
    hashes = {}
    for transformation, sentinel in sentinels_transformed.items():
        sentinel = sentinel.encode("utf-8")
        for algo_name, algo in hash_funcs.items():
            if algo_name.startswith("shake"):
                hash = algo(sentinel).digest(32)
            else:
                hash = algo(sentinel).digest()
            hashes[f"{transformation}" + algo_name] = hash
    return hashes


def transform(sentinel) -> Dict[str, str]:
    transformed_sentinels = {}
    for pre_transform_name, pre_transform in pre_transforms.items():
        for transform_name, transform in transforms.items():
            for post_transform_name, post_transform in post_transforms.items():
                new_sentinel = post_transform(transform(pre_transform(sentinel)))
                if new_sentinel not in transformed_sentinels.values():
                    transformed_sentinels[
                        (f"{pre_transform_name}_" if pre_transform_name != "" else "")
                        + (f"{transform_name}_" if transform_name != "" else "")
                        + (
                            f"{post_transform_name}_"
                            if post_transform_name != ""
                            else ""
                        )
                    ] = new_sentinel
    return transformed_sentinels


def encode(hashes: Dict) -> Dict[str, str]:
    hashes_encoded = {}
    for hash_name, hash in hashes.items():
        for enc_name, encoding in encode_funcs.items():
            hashes_encoded[hash_name + f"_{enc_name}"] = (
                encoding(hash).decode("utf-8").rstrip("=")
            )
    return hashes_encoded


def compute_hashes(sentinel) -> Dict[str, str]:
    transformed_sentinels = transform(sentinel)
    hashes = hash(transformed_sentinels)
    return encode(hashes)


def fuzzy_match(a, b):
    a_trim = a[3:-3]
    b_trim = b[3:-3]
    return a_trim in b or b_trim in a


def find_hashes(hashes, wanted_hash) -> Tuple[List, List]:
    fuzzy_hits = []
    clean_hits = []
    for algo, hash in hashes.items():
        if hash == wanted_hash:
            clean_hits.append(algo)
        else:
            try:
                if fuzzy_match(hash, wanted_hash):
                    fuzzy_hits.append(algo)
            except IndexError:
                continue
    return clean_hits, fuzzy_hits


def print_all_hashes(hashes):
    for algo, hash in hashes.items():
        print(f"{algo:20}: {hash}")


def print_matches(clean_hits, fuzzy_hits, hashes, wanted_hash, sentinel, quiet=False):
    if clean_hits or fuzzy_hits:
        print(f"Found {len(clean_hits)} identical and {len(fuzzy_hits)} fuzzy matches.")
    else:
        if quiet:
            print(f"No matches ({sentinel})")
        else:
            print(f"No matches found.")

    if fuzzy_hits or clean_hits:
        print(40 * "-" + "\n" + f"Wanted hash: {wanted_hash}")
        for algo in clean_hits:
            print(f"Match:       {hashes[algo]} ({algo})")
        for algo in fuzzy_hits:
            print(f"Fuzzy match: {hashes[algo]} ({algo})")


def print_stat(hashes, sentinel):
    print(40 * "-")
    print(f'Sentinel: "{sentinel}"')
    print(
        f"Computed {len(hashes)} hashes for {len(transforms) * len(pre_transforms) * len(post_transforms)} transformations, {len(encode_funcs)} encodings and {len(hash_funcs)} hash functions."
    )


def run(sentinel: str, wanted_hash: Optional[str] = None, quiet=False):
    hashes = compute_hashes(sentinel)

    if not wanted_hash and not quiet:
        print(f"Hashes of {sentinel}:")
        print_all_hashes(hashes)

    if not quiet:
        print_stat(hashes, sentinel)

    if wanted_hash:
        clean_hits, fuzzy_hits = find_hashes(hashes, wanted_hash)
        if len(wanted_hash) < 10:
            fuzzy_hits = []
            if not quiet:
                print("Warning: Short hash input provided, skipping fuzzy search.")
        print_matches(
            clean_hits, fuzzy_hits, hashes, wanted_hash, sentinel, quiet=quiet
        )


def main():
    parser = argparse.ArgumentParser(description="Hash computing tool")
    parser.add_argument(
        "-q",
        "--quiet",
        help="Be less verbose (for batch use)",
        action="store_const",
        dest="quiet",
        const=True,
        default=False,
    )
    parser.add_argument("sentinel", help="The sentinel you want to hash")
    parser.add_argument("hash", nargs="?", help="Optional hash to compare against")
    args = parser.parse_args()
    run(args.sentinel, args.hash, quiet=args.quiet)


if __name__ == "__main__":
    main()
