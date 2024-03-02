import hashlib


def crack_sha1_hash(hash, use_salts=False):
    password = "PASSWORD NOT IN DATABASE"

    # If use salts
    if use_salts:
        # Only difference is that we have nested loop and append the salts at the beginning of the known password line.
        with open("known-salts.txt", "r") as file1:
            for sline in file1:
                read_sline = sline.encode("utf-8").strip()

                with open("top-10000-passwords.txt", "r") as file:
                    for line in file:

                        # Encoding the password line and strip away new line and whitespaces.
                        read_line = line.encode("utf-8").strip()

                        # append salt to the known password and preappend also needed.
                        salted_line_p = read_sline + read_line
                        salted_line_a = read_line + read_sline

                        # Each line hashed and hexdigested
                        hash_line_p = hashlib.sha1(salted_line_p).hexdigest()
                        hash_line_a = hashlib.sha1(salted_line_a).hexdigest()

                        # Found the password decode, then break and return password.
                        if hash_line_p == hash or hash_line_a == hash:
                            password = read_line.decode("utf-8")
                            break
    else:
        with open("top-10000-passwords.txt", "r") as file:
            for line in file:
                # Encoding the password line and strip away new line and whitespaces.
                read_line = line.encode("utf-8").strip()

                # Each line hashed and hexdigested
                hash_line = hashlib.sha1(read_line).hexdigest()

                # Found the password decode, then break and return password.
                if hash_line == hash:
                    password = read_line.decode("utf-8")
                    break

    return password


def main():

    result = crack_sha1_hash("b80abc2feeb1e37c66477b0824ac046f9e2e84a0")
    print(result)


if __name__ == "__main__":
    main()
