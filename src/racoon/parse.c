/*
 * parse.c
 *
 *  Created on: 20150519
 *      Author: wwt
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include "stddef.h"
#include "parse.h"
#include "getopt.h"


void ParamDefault(param_t *param)
{
	memset(param, 0, sizeof(param_t));
	param->isDaemon = 0;
	param->isSpeedTest = 0;
	param->isNoStopTest = 0;
	param->SMType = 2;
	
}


static void Help(param_t *param)
{
#define H0 printf
	H0("<<<<<<<<<<<<<<<<<<<<<<<<Help>>>>>>>>>>>>>>>>>>>>>>>>\n");
	H0("-h, --help       List the more commonly used options\n");
	H0("-d, --daemon     Enable daemon program              \n");		
	H0("-s, --speed      Enable the speed test              \n");
	H0("-n, --nostop     Enable the no stop test            \n");
	H0("-t, --type       SM2/3/4(default type is 2)         \n");
	H0("<<<<<<<<<<<<<<<<<<<<<<<<End>>>>>>>>>>>>>>>>>>>>>>>>>\n");
}


int ParseArgs( int argc, char *argv[], param_t *param)
{
	int c;
	int keylen=0;
	int long_options_index;

	ParamDefault(param);
	
	for(;;)
	{
		long_options_index = -1;
		static struct option long_options[] =
		{
			{ "help",    no_argument,       NULL, 'h' },
			{ "daemon",  no_argument,       NULL, 'd' },
			{ "speed",   no_argument,       NULL, 's' },
			{ "nostop",  no_argument, 		NULL, 'n' },
			{ "type",    required_argument, NULL, 't' },
			{0, 0, 0, 0}
		};
		c = getopt_long( argc, argv, "hdsnt:", long_options, &long_options_index);

		if( c == -1 )
			break;


		switch(c)
		{	
			case 'h':
				Help(param);
				exit(0);
			case 'd':
				param->isDaemon = 1;
				break;
			case 's':
				param->isSpeedTest = 1;
				break;
			case 'n':
				param->isNoStopTest = 1;
				break;
			case 't':
				param->SMType = atoi(optarg);
				break;				
			default:
				break;

		}
	}

	return 0;
}




