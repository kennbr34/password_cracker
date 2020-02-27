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

unsigned int startTime, timeElapsed;
uint32_t trialSeed = 0;
uint32_t startSeed = 0;
float seedsPerSecond;
unsigned int percentilModulo = (unsigned int)(UINT_MAX * .1);
pid_t *cpid, ppid, pid;
int cpuCores;

enum
{
    SITE,
    USER,
    PASS
};

char * const add_opts[] =
{
    [SITE] = "site",
    [USER] = "username",
    [PASS] = "password",
    NULL
};

static struct option longopts[] =
{
    { "help", no_argument,       0, 'h' },
    { "crack", no_argument,       0, 'c' },
    { "threads", required_argument,       0, 't' },
    { "vlevel",  required_argument, 0, 'v' },
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
        "--threads n\n"
        "\tDistribute attack across n number of cores/cpus, instead of all available cores (default).\n\n"
        "--sfrom 0-4294967295 (default 0)\n"
        "\tSpecify where to begin in range of seed values.\n\n"
        "--vlevel 1-5 (default 1)\n"
        "\tVerbosity level. Shows progress at %%10, %%1, %%.1, %%.01, or %%.001 intervals.\n\n"
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

int crack(FILE *dbh, KEY key, HEADER hdr, ENTRY entry)
{
	
	unsigned char buf[BUFLEN] = {0};
	size_t buflen = BUFLEN;
	uint32_t mstrPassSeed = 0;
	int i = 0, nonascii = 0;
	setlocale(LC_NUMERIC, "");
	
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
				fprintf(stdout,"Time elapsed: %u seconds\n", (unsigned int)time(0) - startTime);
				fprintf(stdout,"Pid %i tried %'u seeds in %i seconds, %'.2f seeds per second \n", getpid(), trialSeed - startSeed, timeElapsed, seedsPerSecond);
						
				printf ("\n");
				fflush(stdout);
				fclose(dbh);
				
				return 0;
			}
		}
	}
	
	if(trialSeed > 1 && trialSeed % percentilModulo == 0)
	{
		timeElapsed = time(0) - startTime;
		seedsPerSecond = (float)(trialSeed-startSeed)/timeElapsed;
		fprintf(stderr,"Pid: %i started from seed %'u to %'u, ", getpid(), startSeed, ((UINT_MAX/cpuCores) + startSeed));
		fprintf(stderr,"%'u seeds tried in %i seconds, %'.2f seeds per second \n", trialSeed - startSeed, timeElapsed, seedsPerSecond);
		if(getpid() == ppid)
			fprintf(stderr,"%.3f percent complete, ~%.2f hours left, ~%'.2f seeds per second overall\n", ( ((float)(trialSeed-startSeed)/UINT_MAX) * 100) * cpuCores, ( (((UINT_MAX/cpuCores)-trialSeed-startSeed)/seedsPerSecond) / 3600), seedsPerSecond * cpuCores);
		
		fflush(stderr);
	}
	
	return 1;
}

void signalHandler()
{	
    for(int i=0; i < cpuCores - 1; i++)
		kill(cpid[i],SIGTERM);
	
    kill(ppid,SIGTERM);
    
    exit(0);
}

int main(int argc, char **argv)
{
    char *db = NULL, *site = NULL, *user = NULL, *pass = NULL;
    char *subopt, *value;

    int opts = 0, idx = 0, ret = 0;
    int _init = 0, _crack = 0, _add = 0, _lessthreads = 0, _from = 0;
    
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
                
            case 't':

                _lessthreads++;
                cpuCores = atoi(optarg);
                if(cpuCores == 0)
					cpuCores = get_nprocs();
                break;
                
            case 'f':
				
				_from++;
                sscanf(optarg,"%u",&startSeed);

                break;
                
			case 'v':

                    switch (atoi(optarg))
                    {
                        case 1:
                            percentilModulo = (unsigned int)(UINT_MAX * .1);
                            break;
                        case 2:
                            percentilModulo = (unsigned int)(UINT_MAX * .01);
                            break;
                        case 3:
                            percentilModulo = (unsigned int)(UINT_MAX * .001);
                            break;
                        case 4:
                            percentilModulo = (unsigned int)(UINT_MAX * .0001);
                            break;
                        case 5:
                            percentilModulo = (unsigned int)(UINT_MAX * .00001);
                            break;
                        default:
                            percentilModulo = (unsigned int)(UINT_MAX * .1);
                    }

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
		
		startTime = time(0);
				
		if (_from)
			trialSeed = startSeed;
		
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
		
		signal(SIGINT, signalHandler);
		
		while( trialSeed < UINT_MAX)
		{
		
				if ((ret = crack(dbh, key, hdr, entry)) == 0)
				{
					if(getpid() != ppid)
						kill(ppid,SIGINT);
					else
						for(int i=0; i < cpuCores - 1; i++)
							kill(cpid[i],SIGINT);
				}
				trialSeed++;
		}
		
		
		
		
        return ret;
    }

    return -1;
}
