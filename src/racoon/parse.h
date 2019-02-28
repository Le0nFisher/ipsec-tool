
#ifndef __PARSE_H__
#define __PARSE_H__






typedef struct param_t{
	unsigned char	isSpeedTest;
	unsigned char	isNoStopTest;
	unsigned char	isDaemon;
	unsigned char	SMType;
	unsigned char* 	run_stat_out;
}param_t;







int ParseArgs( int argc, char *argv[], param_t *param);







#endif
