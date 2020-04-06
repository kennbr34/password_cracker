/* "Military-Grade Password Cracker" - Hushcon 2015 CTF  */
/* Public domain 2019, kennbr34@gmail.com, epixoip@hushcon.com              */
/* cc -g -W -Wall -o passwd_cracker passwd_cracker.c             */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <assert.h>
#include <errno.h>
#include <time.h>
#include <limits.h>
#include <sys/sysinfo.h>
#include <sys/types.h>
#include <signal.h>
#include <ctype.h>
#include <locale.h>

typedef struct {
    #define KEYLEN 256
    uint32_t state[KEYLEN];
} KEY;

typedef struct {
    #define BUFLEN 16
    uint32_t version;
    unsigned char master_pass[BUFLEN];
} HEADER;

typedef struct {
    unsigned char site[BUFLEN * 2];
    unsigned char user[BUFLEN];
    unsigned char pass[BUFLEN];
} ENTRY;

uint32_t trialSeed = 0;
uint32_t startSeed = 0;

uint32_t *d_trialSeed;

uint32_t *cudaThreadSeed;
uint32_t *d_cudaThreadSeed;

__device__ HEADER d_hdr;

unsigned char master_pass[BUFLEN];
unsigned char *d_master_pass;

/*Not sure what a good default for this is*/
uint32_t cudaThreads = 1024;
uint32_t cudaBlocks = 8192;
uint32_t totalThreads = cudaThreads * cudaBlocks;

__device__ int passFound = 0;

static struct option longopts[] =
{
    { "help", no_argument,       0, 'h' },
    { "crack", no_argument,       0, 'c' },
    { "blocks", required_argument,       0, 'b' },
    { "sfrom",  required_argument, 0, 'f' },
    { 0,      0,                 0,  0  }
};

void help()
{
    fprintf(stderr,
        "\nMilitary-Grade Password Cracker\n"
        "Usage: ./passwd_cracker [options] [suboptions] <database>\n\n"
        "--crack\n"
        "\tBrute force the database\n\n"
        "--blocks n\n"
        "\tDistribute attack across n number of CUDA blocks.\n\n"
        "--sfrom 0-4294967295 (default 0)\n"
        "\tSpecify where to begin in range of seed values.\n\n"
    );
}

void derive_key(KEY *key, uint32_t trialSeed)
{

    int i = 0;

    srand(trialSeed);
    
    for (i = 0; i < KEYLEN; i++)
        key->state[i] = rand() & 0xffff;
}

void encrypt(KEY *key, unsigned char *data, const size_t len)
{
    uint32_t i = 0, t = 0, x = 0, y = 0;
    uint32_t state[KEYLEN];

    memcpy(&state, key->state, sizeof(state));

    for (; i < len; i++)
    {
        x = (x + 1) % KEYLEN;
        y = (y + state[x]) % KEYLEN;

        t = state[x];
        state[x] = state[y];
        state[y] = t;

        t = (state[x] + state[y]) % KEYLEN;
        data[i] = state[t] ^ data[i];
    }
}

/*An implementation of glibc's rand() that will produce the same values for respective seed value*/
/*This is needed since I can't call rand() from a kernel and it MUST produce the same values that glibc's would*/
__device__ uint32_t randInt(uint32_t seed, uint32_t nSeedUse) {
    /*If this is not shared memory then is slows down the performance dramatically*/
    /*Set to 600 because in addition to the first 344 values it must hold 256 values for the size of the key */
    int r[600];
    
    /*This must be kept static so that successive calls to the function produce the correct next random value per seed*/
    static int i;
  
  if(seed == 0)
    seed++;

  r[0] = seed;
  for (i=1; i<31; i++) {
    r[i] = (16807LL * r[i-1]) % 2147483647;
    if (r[i] < 0) {
      r[i] += 2147483647;
    }
  }
  for (i=31; i<34; i++) {
    r[i] = r[i-31];
  }
  for (i=34; i<344; i++) {
    r[i] = r[i-31] + r[i-3];
  }

  /*nSeedUse represents the number of times this seed has been used*/
  r[344 + nSeedUse] = r[(344 + nSeedUse)-31] + r[(344 + nSeedUse)-3];
  
  return (unsigned int)r[344 + nSeedUse] >> 1;
}


__device__ void d_derive_key(KEY *d_key, uint32_t trialSeed)
{

    int i;
    i = 0;
    
    for (i = 0; i < KEYLEN; i++) {
        __syncthreads();
        d_key->state[i] = randInt(trialSeed, i) & 0xffff;
    }
}

__device__ void d_encrypt(KEY *d_key, unsigned char *data, const size_t len)
{
    uint32_t i, t, x, y;
    i = 0;
    t = 0;
    x = 0; 
    y = 0;
    
    for (i = 0; i < len; i++)
    {
        x = (x + 1) % KEYLEN;
        y = (y + d_key->state[x]) % KEYLEN;

        t = d_key->state[x];
        d_key->state[x] = d_key->state[y];
        d_key->state[y] = t;

        t = (d_key->state[x] + d_key->state[y]) % KEYLEN;
        data[i] = d_key->state[t] ^ data[i];
    }
}

/*A replacement of strlen() to be called in a kernel*/
__device__ int stringLength(unsigned char *string)
{
    int i;
    i = 0;
    while(string[i] != '\0') {
        i++;
    }
    
    return i;
}

/*A replacement for isprint() to be called in a kernel*/
__device__ int isPrintable(unsigned char c)
{
    if(c >= 32 || c <= 126)
        return 1;
    else
        return 0;
}

__device__ int crack(unsigned char *master_pass, uint32_t trialSeed, uint32_t *foundSeed)
{
    
    /*This will stop other blocks from executing further if the password has already been found*/
    if(passFound == 1)
             return 0;
    
	unsigned char buf[BUFLEN];
    memset(buf,0,BUFLEN);
	uint32_t mstrPassSeed;
    mstrPassSeed = 0;
	int i = 0, nonprintable = 0;
    
    KEY d_key;
    
    /*This MUST be local so that each block has its own copy of the master_pass.  Otherwise one block may change it before the other has confirmed it decrypted correctly*/
    unsigned char masterPassLocal[BUFLEN];
    memcpy(masterPassLocal,master_pass,sizeof(unsigned char) * BUFLEN);
    	
	d_derive_key(&d_key, trialSeed);
    	
	d_encrypt(&d_key, masterPassLocal, BUFLEN);
        
    /*If the last byte of the resulting decryption is a null byte it MIGHT be the null-terminated password*/
	if (masterPassLocal[BUFLEN-1] == '\0')
	{
        
        /*FIXME: Maybe this would be faster as a memcpy call instead*/
        for(i = 0; i < stringLength(masterPassLocal) ; i++) {
            buf[i] = masterPassLocal[i];
        }
        
        /*Serialize the resulting decryption and see if the integer it produces matches the trialSeed*/		
		for (i = 0; i < BUFLEN - 4; i+=4)
			mstrPassSeed ^= (uint32_t) buf[i+0] <<  0
				| (uint32_t) buf[i+1] <<  8
				| (uint32_t) buf[i+2] << 16
				| (uint32_t) buf[i+3] << 24;
        
        /*If the resulting decryption produces the same integer as the trialSeed and it's a null-terminated string it's probably the password*/
		if(trialSeed == mstrPassSeed)
		{   
            
            printf("Master pass: %s\n", masterPassLocal);
                printf("Seed value: %u\n", trialSeed);
                
            /*Test the resulting decryption for any non-printable characters*/
            for(i = 0; i < BUFLEN; i++)
			{
				if(!isPrintable(masterPassLocal[i]))
					nonprintable++;
			}
            
            /*If it contains no non-printable characters then it is surely the password*/
            if(!nonprintable) {
                
                *foundSeed = trialSeed;
                passFound = 1;
            
                return 0;
            }
		}
	}
	
	return 1;
}

__global__ void distributeAndCrack(uint32_t *seedArray, unsigned char *master_pass, uint32_t *foundSeed) 
{
    int index = threadIdx.x + blockIdx.x * blockDim.x;
        
    /*seedArray is an array of integers with each being the starting seed value each block should start at*/
    uint32_t trialSeed;
    trialSeed = seedArray[index];
        
    /*Was hoping that making the copy of the encrypted master pass that gets sent to crack() will be faster if it's in shared memory*/    
    unsigned char sharedMasterPass[BUFLEN];
    memcpy(sharedMasterPass,master_pass,sizeof(unsigned char) * BUFLEN);
            
    /*Iterate each block from its start seed up until the next block's start seed or until UINT_MAX if that seed would extend beyond array*/
    while( trialSeed < index + 1 < (blockDim.x * gridDim.x) ? seedArray[index] : UINT_MAX)
    {
        
        if (crack(sharedMasterPass, trialSeed, foundSeed) == 0)
        {
            asm("exit;");
        }
        trialSeed++;
    }
}


int main(int argc, char **argv)
{
    char *db = NULL;

    int opts = 0, idx = 0, ret = 0;
    int _crack = 0, _setbocks = 0, _from = 0;
    
    startSeed = 0;
    
    KEY key;
    HEADER hdr;
    ENTRY entry;
    FILE *dbh;

    while (1)
    {
        if ((opts = getopt_long_only(argc, argv, "", longopts, &idx)) == -1)
            break;

        switch (opts)
        {
            case 0:

                if (longopts[idx].flag)
                    break;

            case 'h':

                help();
                return 0;

            case 'c':

                _crack++;
                break;
                
            case 'b':

                _setbocks++;
                cudaThreads = atoi(optarg);
                break;
                
            case 'f':
				
				_from++;
                sscanf(optarg,"%u",&startSeed);

                break;
                
            default:
                abort();
        }
    }

    if (optind == argc)
    {
        fprintf(stderr, "Error: database required\n");

        return -1;
    }

    assert(db = strdup(argv[optind]));

    if (_crack)
    {				
                
		if ((dbh = fopen(db, "r")) == NULL)
        return errno;

		fread(&hdr, sizeof(hdr), 1, dbh);
    
		fread(&entry, sizeof(entry), 1, dbh);
		                
        cudaThreadSeed = (uint32_t *)malloc(sizeof(uint32_t) * totalThreads);
        
        /*This loop will divvy up the range of seeds to try equally per the amount of blocks and store the start of each block's range into an integer in the array*/        
        for(int i=1; i < totalThreads; i++)
        {
            cudaThreadSeed[i] = (((UINT_MAX-startSeed)/totalThreads) * i + startSeed);
        }
        
        /*This will allow the first block to be started at a different seed value if specified*/
        cudaThreadSeed[0] = startSeed;
        
        cudaMalloc((void **)&d_cudaThreadSeed, sizeof(uint32_t) * totalThreads);
        cudaMemcpy(d_cudaThreadSeed, cudaThreadSeed, sizeof(uint32_t) * totalThreads, cudaMemcpyHostToDevice);
        
        /*The master password is stored encrypted in the header, so load it up to attempt trial decryptions on*/
        memcpy(&master_pass,&hdr.master_pass,sizeof(hdr.master_pass));
        
        cudaMalloc((void **)&d_master_pass, sizeof(master_pass));
        cudaMemcpy(d_master_pass, master_pass, sizeof(master_pass), cudaMemcpyHostToDevice);
        
        cudaMalloc((void **)&d_trialSeed, sizeof(uint32_t));
        cudaMemcpy(d_trialSeed,&trialSeed,sizeof(uint32_t), cudaMemcpyHostToDevice);
        
        /*This kernel will start each block off at the proper seed value and launch the brute-force attack*/
        /*When the proper seed value is found it will be stored into d_trialSeed*/                   
        distributeAndCrack<<<cudaBlocks,cudaThreads>>>(d_cudaThreadSeed, d_master_pass, d_trialSeed);
        cudaDeviceSynchronize();
        
        cudaMemcpy(&trialSeed,d_trialSeed,sizeof(uint32_t), cudaMemcpyDeviceToHost);
        
        /*Now that the proper seed has been found, it can be used to decrypt and print the database*/
            
        derive_key(&key, trialSeed);
        
        encrypt(&key, hdr.master_pass, BUFLEN);
        
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
        
        printf ("\n");
        fflush(stdout);
        fclose(dbh);
		
        return ret;
    }

    return -1;
}
