# passwd_cracker
My solution to [HushCon 2015 "Military Strength Password Manager"](https://github.com/HushCon/password_manager)

I ended up going with a brute force attack because I felt like it was the easiest to pull off, and the password manager code could be repurposed to drive the brute-forcing. I put a rough POC program together in a couple of hours and then decided to make it multi-threaded to take advantage of my quad core CPU. It can test ~750k keys per second on my very old Phenom X4 9950 @ 2.6Ghz and this means it will take about an hour and a half (or less) to find the right key.

It was tricky to work out the multi-threading because I had never done any parallel programming before, but it's pretty simple. Boiled down, each thread is given its equal proportion of possible key values to test, so multiple ranges of the possible key values can be searched concurrently. As soon as one thread finds the correct key value, it prints the database contents, along with the master password, and kills the other threads.

# The attack in a nutshell

1. Derive a key with a trial seed
2. Decrypt master pass in header with trial key
3. If the result is a null-terminated string, derive a seed value using the KDF with the decrypted string as input
4. If the seed derived matches the trial seed, and the string consists of all ASCII values, the key that encrypted the master password was found.

# All vulnerabilities I noticed

1. (Used in attack) Known Plain-Text: Input buffers were zeroed before having user-input copied to them and left null-terminated, so null-bytes can be expected to occur, and at known offsets.
2. (Used in attack) Weak KDF: The KDF merely takes the bit values of the ASCII characters entered as a password, and serializes them into a seed to derive a key using rand()
3. (Used in attack) Insufficient seed size: The seed value ultimately used to derive a key is a 32-bit integer, so has only 2^32 possible values.
4. (Used in attack) Master Password Stored Unhashed: The master password is stored encrypted, but unhashed, so it can be used for verifying trial keys and ultimately recovered along with the database contents.
5. Leaked Key Information: Because a XOR encryption operation is used, the zero bytes in the buffers will be converted to the key bytes and written to file.
6. Multiple Time Pads: Because there is no nonce, the key stream used to encrypt one entry is reused to encrypt every successive entry, creating a database of concatenated pads reusing the same key.

# Analysis and Attack Development

I started out looking at the general flow of the program to see how it was performing the encryption and storing information to file. I immediately noticed that the master password was encrypted and stored in the header as a means to check if the password was correct or not.

###### Method to test if the correct password was entered
```C
       derive_key(&key, master, strlen((char *) master));
        encrypt(&key, hdr.master_pass, BUFLEN);

        if (strlen((char *) master) == strlen((char *) hdr.master_pass) &&
            memcmp(master, hdr.master_pass, strlen((char *) master)) == 0
           ) break;

        encrypt(&key, hdr.master_pass, BUFLEN);

        printf("\nIncorrect password!\n\n");
        sleep(1);
```

I knew this meant that I could use this for confirmation of a successful brute-force attack, and set out to see how it might be vulnerable in such a way.  I started by looking at the encryption algorithm thinking it might have been a simple XOR, but it looked like RC4.  While that has its own vulnerabilities, I felt like there was probably a weaker link in the KDF.

###### Key derivation function
```C
void derive_key(KEY *key, unsigned char *pass, const size_t len)
{
    unsigned char buf[BUFLEN] = {0};
    size_t buflen = BUFLEN;
    **uint32_t seed = 0;**
    int i = 0;

    if (len < BUFLEN)
        buflen = len;

    memcpy(&buf, pass, buflen);

    for (; i < BUFLEN - 4; i+=4)
        seed ^= (uint32_t) buf[i+0] <<  0
              | (uint32_t) buf[i+1] <<  8
              | (uint32_t) buf[i+2] << 16
              | (uint32_t) buf[i+3] << 24;

    srand(seed);

    for (i = 0; i < KEYLEN; i++)
        key->state[i] = rand() & 0xffff;
}
```

Paydirt! 

This KDF simply uses serialization to turn the ASCII values of the password into a 32-bit seed value that's used to derive the key.  Because the 32-bit space only allows 2^32 possible seed values, I knew I could derive the right key by brute-forcing the right seed value within 2^32 tries.  Then because the key-derivation and encryption/decryption is so simple, I knew this meant I could perform enough test derivations and decryptions per second to brute-force it in a practical amount of time.

So now I simply needed to formulate a way to test trial seed candidates, derive a key using that seed, and test if it decrypts properly with that key.  Knowing that the master password was stored unhashed in the master header and used to test if the password was entered correctly, I knew I could use that to confirm if the correct key was used by decrypting the header and testing the result.  The main problem now was how my program would know if the resulting password was correct or not.

That's where the 1st vulnerability came in.  Because the master password buffer was set to 0 before recieving user input, this meant that the string would be null-terminated, and I knew I could test for that known plaint-text as confirmation that the password was properly decrypted.

###### Method for recieving the master password
```C       
        size_t len = BUFLEN;
        unsigned char *master, *verify;

        master = (unsigned char *) getpass("Select master password  : ");

        if (strlen((char *) master) < BUFLEN)
            len = strlen((char *) master);

        memset(&hdr.master_pass, 0, sizeof(hdr.master_pass));
        memcpy(&hdr.master_pass, master, len);
```
       
Of course, there was still the off-chance that even if garbage data was the result of an erroneous decryption, that it might also have a '0' byte that would appear to be a null-terminator and cause a false-positive.  So in order to compensate, the confirmation process was two-fold.  First I would test for null-terminator at the end of the resulting decryption, and if it was present, I would then test to ensure that all values of it were in the ASCII range.  If both a null-terminator was found, and the string contained all ASCII values, then I would print the decrypted master password, as well as decrypt and print the contents of the database.

###### Confirming the trial seed derived the correct key
```C
  derive_key(&key, trialSeed);
	
	encrypt(&key, hdr.master_pass, BUFLEN);
	
	if (hdr.master_pass[BUFLEN] == '\0')
	{
		
		memcpy(&buf, hdr.master_pass, strlen(hdr.master_pass));
		
		for (; i < BUFLEN - 4; i+=4)
			mstrPassSeed ^= (uint32_t) buf[i+0] <<  0
				| (uint32_t) buf[i+1] <<  8
				| (uint32_t) buf[i+2] << 16
				| (uint32_t) buf[i+3] << 24;
		
		if(trialSeed == mstrPassSeed)
		{
			for(i = 0; i < BUFLEN; i++)
			{
				if(!isascii(hdr.master_pass[i]))
					nonascii++;
			}
		
			if(!nonascii)
			{
				encrypt(&key, entry.site, sizeof(entry.site));
				encrypt(&key, entry.user, sizeof(entry.user));
				encrypt(&key, entry.pass, sizeof(entry.pass));
				
				fprintf(stdout,"\n%-32s\t%-16s\t%-16s\n", "SITE", "USERNAME", "PASSWORD");
				fprintf(stdout,"--------------------------------");
				fprintf(stdout,"--------------------------------");
				fprintf(stdout,"----------------\n");
				
				fprintf(stdout,"%-32s\t%-16s\t%-16s\n", entry.site, entry.user, entry.pass);
				
				
				while (!feof(dbh) && fread(&entry, sizeof(entry), 1, dbh) == 1)
				{
					encrypt(&key, entry.site, sizeof(entry.site));
					encrypt(&key, entry.user, sizeof(entry.user));
					encrypt(&key, entry.pass, sizeof(entry.pass));
					
					printf("%-32s\t%-16s\t%-16s\n", entry.site, entry.user, entry.pass);
				}
			
				fprintf(stdout,"Master Pass: %s\n", hdr.master_pass);
				fprintf(stdout,"Seed value: %u\n", trialSeed);
 ```
 
# Application Development and Assessment

Now that I had an attack strategy to brute-force the seed value, and a way to confirm that I got the correct seed value and print the master password and the database contents, I needed to make sure it could be done in a practical amount of time. I modified the existing program to leverage it into a brute-forcing application, and created some code to time the amount of trial seeds tested per second. I determined I could try about 187k seeds per second on my old Phenom X4. This would mean it would take, at most, just a little over 6 hours to find the correct seed. 

I did not actually attend this convention but merely found this GitHub page later on, so I don't know what the actual time limit was.  I assume that 6 hours would have fit into the time-frame of a convention. The original GitHub page also said that there were **teams** working on this, so I considered that development time would have been considerably shorter if it weren't just myself working on this, and it still only took a couple hours on my own.  I also considered that if there were multiple team members with multiple computers, we could distribute the attack over multiple computers by divying up the range of seed values to try. So all told, I estimated that this attack could be conducted successfully in at most 8 hours even by only one person using antiquated hardware, with that time reduced by half per each team member.

Finally, going off the distributed-attack concept, I realized I could distribute the attack in the same way over multiple cores as if they were multiple computers. I accomplished this by dividinge the amount of seeds to test among the total number of cores available, forking off to work on the first quarter of the 2^32 range, forking again to work on the second quarter of the 2^32 range, and so on until the entire range of seeds would be evenly distributed over multiple forked processes.  This was a little tricky, but I figured out a way to do it while also detecting the available cores for a CPU so that it could run even faster on more modern hardware. On a 8 core Ryzen 7 1700 this is able to try ~3 million seeds per second (with hyper-threading) bringing the total possible attack time down to under 40 minutes.

###### Distributing seed range to test over multiple cores
```C
    ppid = getpid();
		
		if (!_lessthreads)
			cpuCores=get_nprocs();
			
		cpid = calloc(sizeof(pid_t),cpuCores);
		
		for(int i=0; i < cpuCores - 1; i++)
		{
			if(getpid() == ppid)
			{
				if(fork() == 0)
					cpid[i] = getpid();
			}
			if(getpid() == cpid[i])
			{
				trialSeed = (((UINT_MAX-startSeed)/cpuCores) * (i + 1) + startSeed);
			}
			
			startSeed = trialSeed;
		}
```
This could be distributed further among multiple team members' computers by assigning a specific seed range to each member, with this specified range also divided among each team member's multiple cores.  This means that with just a handful of team members, and even moderately powered CPUs, the attack could successfully be performed in less time than it would take to deliver a pizza.


