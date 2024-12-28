import secrets
import string

from Crypto.Hash import  MD5

#На тот случай, если файл с хешами и паролями уже есть
def get_passwords():
    passwords = []
    try:
        with open('words.txt', mode="r") as file:
            lines = file.read().split("\n")
        for line in lines:
            passwords.append(line.encode())
    except Exception as e:
        print(f"Error: {e}")
        return None

    return passwords


def get_hashes(passwords):
    result = []
    if passwords is None:
        return
    else:
        for password in passwords:
            result.append(MD5.new(password).hexdigest())
    return result


def generate_random_string(length = 8):
    characters = string.ascii_letters + string.digits
    return ''.join(secrets.choice(characters) for _ in range(length))


def generate_random_passwords(length = 8, count = 10):
    result = []
    for i in range(count):
        result.append(generate_random_string(length))

    return result


def append_passwords_to_file(passwords):
    try:
        with open('words.txt', mode="a+") as file:
            for password in passwords:
                file.write(password + '\n')
    except Exception as e:
        print(f"Error: {e}")
        return None


def append_hashes_to_file(hashes):
    try:
        with open('words.txt', mode="a+") as file:
            for h in hashes:
                file.write(h + '\n')
    except Exception as e:
        print(f"Error: {e}")
        return None


def main():
    random_passwords = generate_random_passwords(50)
    append_passwords_to_file(random_passwords)
    print('-----------------PASSWORDS-----------------')
    for password in random_passwords:
        print(password)
    print('-----------------HASHES-----------------')
    hashes = get_hashes(get_passwords())
    append_hashes_to_file(hashes)
    if hashes is not None:
        for hash_from_hashes in hashes:
            print(hash_from_hashes)


if __name__ == "__main__":
    main()
