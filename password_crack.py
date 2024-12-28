import multiprocessing
from multiprocessing import Pool
import sys
import time

from Crypto.Hash import MD4, MD5, SHA1, SHA256, SHA512


def get_hash_function(hash_algo_name):
    algo_mapping = {
        'md4': MD4,
        'md5': MD5,
        'sha1': SHA1,
        'sha256': SHA256,
        'sha512': SHA512
    }
    return algo_mapping.get(hash_algo_name)


def get_hash(hash_function, data):
    return hash_function.new(data).hexdigest()


def get_data_from_file(filename, encoding):
    try:
        with open(filename, mode="r", encoding=encoding) as file:
            return [line.strip().encode(encoding) for line in file if line.strip()]
    except Exception as e:
        print(f"Error reading file '{filename}': {e}")
        return []


def check_chunk_data(chunk, hashes, hash_algo):
    function = get_hash_function(hash_algo)
    if function is None:
        return []

    local_results = []
    for password in chunk:
        password_hash = get_hash(function, password)
        if password_hash.encode() in hashes:
            local_results.append((password.decode(), password_hash))
    return local_results


def split_list(data, num_chunks):
    return [data[i::num_chunks] for i in range(num_chunks)]


def main():
    args = sys.argv
    if len(args) != 5:
        print("Usage: script.py <words_file> <encoding> <hash_algo> <hashes_file>")
        return -1

    words_file = args[1]
    encoding = args[2]
    hash_algo = args[3]
    hashes_file = args[4]

    data = get_data_from_file(words_file, encoding)
    hashlist = set(get_data_from_file(hashes_file, encoding))

    if not data or not hashlist:
        print("Error: Input files are empty or invalid.")
        return -1

    # Single-threaded
    start_time = time.time()
    result_single_thread = check_chunk_data(data, hashlist, hash_algo)
    end_time = time.time()

    print(f"Elapsed time in single-thread mode: {end_time - start_time:.4f} seconds")
    for password, matched_hash in result_single_thread:
        print(f"{password}:{matched_hash}")

    num_cores = multiprocessing.cpu_count() // 2
    chunks = split_list(data, num_cores)

    start_time = time.time()
    with Pool(processes=num_cores) as pool:
        results = pool.starmap(check_chunk_data, [(chunk, hashlist, hash_algo) for chunk in chunks])

    matched = [item for sublist in results for item in sublist]
    end_time = time.time()

    print('----------------------------------')
    print(f"Elapsed time in multi-thread mode: {end_time - start_time:.4f} seconds")
    for password, matched_hash in matched:
        print(f"{password}:{matched_hash}")

    print(len(matched))
    return 0


if __name__ == "__main__":
    main()
