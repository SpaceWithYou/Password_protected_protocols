import multiprocessing
import sys

from Crypto.Hash import MD4, MD5, SHA1, SHA256, SHA512


def get_hash_function(hash_algo_name):
    algo_mapping = {
        'md4': MD4,
        'md5': MD5,
        'sha1': SHA1,
        'sha256': SHA256,
        'sha512': SHA512
    }

    algo = algo_mapping.get(hash_algo_name)

    if algo is None:
        print(f"Algorithm '{hash_algo_name}' is not supported.")
        return None
    else:
        return algo


def get_hash(hash_function, data):
    return hash_function.new(data).hexdigest()


def get_data_from_file(filename, encoding):
    result = []
    #На одной строке - один хеш/пароль
    try:
        with open(filename, mode="r", encoding=encoding) as file:
            lines = file.read().split("\n")
        for line in lines:
            result.append(line.encode(encoding))
    except Exception as e:
        print(f"Error: {e}")

    return result


def check_chunk_data(chunk, hashes, result, hash_algo):
    function = get_hash_function(hash_algo)
    if function is None:
        return -1

    for password in chunk:
        password_hash = get_hash(function, password)
        for hash_from_list in hashes:
            if password_hash.encode() == hash_from_list:
                result.put((password, hash_from_list))
                break


def main():
    args = sys.argv
    if len(args) != 5:
        print("Error")
        return -1

    words = args[1]
    encoding = args[2]
    hash_algo = args[3]
    hashes = args[4]

    data = get_data_from_file(words, encoding)
    hashlist = get_data_from_file(hashes, encoding)

    num_processes = multiprocessing.cpu_count()
    chunks = [data[i::num_processes] for i in range(num_processes)]
    result = multiprocessing.Queue()

    processes = []
    for chunk in chunks:
        #Проверяем пароли
        p = multiprocessing.Process(target=check_chunk_data, args=(chunk, hashlist, result, hash_algo))
        processes.append(p)
        p.start()

    for p in processes:
        p.join()

    while not result.empty():
        password, matched = result.get()
        print(f"{password.decode(encoding)}:{matched}")

    return 0


if __name__ == "__main__":
    main()
