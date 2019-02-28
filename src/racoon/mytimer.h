/*
 * mytimer.h
 *
 *  Created on: 2015Äê3ÔÂ25ÈÕ
 *      Author: wwt
 */

#ifndef MYTIMER_H_
#define MYTIMER_H_

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/time.h>


int GetTimeTick(struct timeval* Time);


int GetTimeDiff(struct timeval* Diff, struct timeval* Start, struct timeval* Stop);



#endif /* MYTIMER_H_ */
