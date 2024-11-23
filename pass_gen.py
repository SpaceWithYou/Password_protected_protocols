import secrets
import string
import sys

from Crypto.Hash import MD4, MD5, SHA1, SHA256, SHA512

def get_hash(hash_algo_name, data):
    algo_mapping = {
        'md4' : MD4,
        'md5' : MD5,
        'sha1' : SHA1,
        'sha256' : SHA256,
        'sha512' : SHA512
    }

    algo = algo_mapping.get(hash_algo_name)

    if algo is None:
        print(f"Algorithm '{hash_algo_name}' is not supported.")
        return None
    else:
        return algo.new(data).hexdigest()

def generate_random_string(length):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))

def get_passwords_from_file(filename, encoding):
    result = []
    #На одной строке - один пароль
    try:
        with open(filename, mode="r", encoding=encoding) as file:
            lines = file.read().split("\n")
        for line in lines:
            result.append(line.encode(encoding))
    except Exception as e:
        print(f"Error: {e}")

    return result

def get_hashes_from_passwords(passwords, hash_count, hash_algo):
    result = []
    counter = 0
    for password in passwords:
        if counter < hash_count:
            counter += 1
            result.append(get_hash(hash_algo, password))
        else:
            result.append(generate_random_string(len(password)))

    return '\n'.join(result)

def write_hashes(filename, encoding, hashes):
    try:
        with open(filename, "w", encoding=encoding) as file:
           file.write(hashes)
    except Exception as e:
        print(f"Error: {e}")

def main():
    args = sys.argv
    if len(args) != 8:
        print("Error")
        return -1

    input_file = args[3]
    encoding = args[4]
    hash_algo = args[5]
    hash_count = int(args[6])
    output_file = args[7]

    passwords = get_passwords_from_file(input_file, encoding)
    hashes = get_hashes_from_passwords(passwords, hash_count, hash_algo)
    write_hashes(output_file, encoding, hashes)
    return 0

if __name__ == "__main__":
    main()