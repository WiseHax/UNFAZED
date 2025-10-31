import hashlib

def get_hashes(file_path):
    hashes = {
        "MD5": hashlib.md5(),
        "SHA1": hashlib.sha1(),
        "SHA256": hashlib.sha256()
    }

    with open(file_path, "rb") as f:
        while chunk := f.read(4096):
            for algo in hashes.values():
                algo.update(chunk)

    return {name: h.hexdigest() for name, h in hashes.items()}
