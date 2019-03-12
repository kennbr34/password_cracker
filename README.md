# passwd_cracker
My solution to [HushCon 2015 "Military Strength Password Manager"](https://github.com/HushCon/password_manager)

I ended up going with a brute force attack because I felt like it was the easiest to pull off, and the password manager code could be repurposed to drive the brute-forcing. I put a rough POC program together in a couple of hours and then decided to make it multi-threaded to take advantage of my quad core CPU. It can test ~750k keys per second on my very old Phenom X4 9950 @ 2.6Ghz and this means it will take about an hour and a half (or less) to find the right key.

It was tricky to work out the multi-threading because I had never done any parallel programming before, but it's pretty simple. Boiled down, each thread is given its equal proportion of possible key values to test, so multiple ranges of the possible key values can be searched concurrently. As soon as one thread finds the correct key value, it prints the database contents, along with the master password, and kills the other threads.

The attack in a nutshell:
1. Derive a key with a trial seed
2. Decrypt master pass in header with trial key
3. If the result is a null-terminated string, derive a seed value using the KDF with the decrypted string as input
4. If the seed derived matches the trial seed, and the string consists of all ASCII values, the key that encrypted the master password was found.

All vulnerabilities I noticed:

1. (Used in attack) Known Plain-Text: Input buffers were zeroed before having user-input copied to them and left null-terminated, so null-bytes can be expected to occur, and at known offsets.
2. (Used in attack) Weak KDF: The KDF merely takes the bit values of the ASCII characters entered as a password, and serializes them into a seed to derive a key using rand()
3. (Used in attack) Insufficient seed size: The seed value ultimately used to derive a key is a 32-bit integer, so has only 2^32 possible values.
4. (Used in attack) Master Password Stored Unhashed: The master password is stored encrypted, but unhashed, so it can be used for verifying trial keys and ultimately recovered along with the database contents.
5. Leaked Key Information: Because a XOR encryption operation is used, the zero bytes in the buffers will be converted to the key bytes and written to file.
6. Multiple Time Pads: Because there is no nonce, the key stream used to encrypt one entry is reused to encrypt every successive entry, creating a database of concatenated pads reusing the same key.
