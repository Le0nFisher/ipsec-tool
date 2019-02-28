/*
 * timer.c
 *
 *  Created on: 20150519
 *      Author: wwt
 */



#include "mytimer.h"



int GetTimeTick(struct timeval* Time)
{
	gettimeofday(Time, 0);
	return 0;
}

int GetTimeDiff(struct timeval* Diff, struct timeval* Start, struct timeval* Stop)
{
	if(Stop->tv_usec >= Start->tv_usec)
		Diff->tv_usec = Stop->tv_usec - Start->tv_usec;
	else
	{
		if(Stop->tv_sec > Start->tv_sec)
		{
			Stop->tv_sec -=1;
			Diff->tv_usec = 1000000 + Stop->tv_usec - Start->tv_usec;
		}else
			return -1;
	}

	if(Stop->tv_sec >= Start->tv_sec)
			Diff->tv_sec = Stop->tv_sec - Start->tv_sec;
		else
			return -1;
	return 0;

}
