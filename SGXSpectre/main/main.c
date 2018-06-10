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
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>


#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

#include "enclave_u.h"
#include "enclave_init.h"
#include "MIC.h"


extern sgx_enclave_id_t global_eid;

static void print_ecall(ecall_val* eval)
{
        printf("THIS IS CURRENT ECALL PACKET:\n type: %d\n x : %d\n array2: %ld\n array1_size: %ld\n malicious_x: %d\n",eval->type, (int)eval->x, (long)eval->array2, (long)eval->array1_size, (int)eval->malicious_x);
}


static size_t socket_ecall_offset()
{
	size_t malicious_x;
	sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;
	
	sgx_ret = ecall_get_offset(global_eid, &malicious_x);
	if(sgx_ret != SGX_SUCCESS){
		printf("SGX ECALL OFFSET FAIL: %0x\n", sgx_ret);
		abort();
		return -1;
	}
	printf("$$$$$$$$$\n%ld\n",malicious_x);
	return malicious_x;
}


static int socket_ecall_victim_function(ecall_val* in)
{
	sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;
	sgx_ret = ecall_victim_function(global_eid, in->x, in->array2, in->array1_size);
	if(sgx_ret !=SGX_SUCCESS){
		printf("ECALL_VICTIM FAIL\n")
		abort();
		return -1;
	}
	return 0;
}

int socket_init( int port_num)
{
	int fd_sock, cli_sock;
	int ret;
	struct sockaddr_in addr;
	ssize_t len;
	
	fd_sock = socket(AF_INET, SOCK_STREAM, 0);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htons (INADDR_ANY);
	addr.sin_port = htons (port_num);
	ret = bind (fd_sock, (struct sockaddr *)&addr, sizeof(addr));
	if( ret == -1){
		printf("socket listen error\n");
		close(fd_sock);
		return -1;
	}
	
	while(1){
		//listen
		ret = listen(fd_sock, 0);
		if(ret < 0){
			printf("Listen error\n");
			close(fd_sock);
			return -1;
		}

		cli_sock = accept(fd_sock, (struct sockaddr *)NULL, NULL);
		if(cli_sock == -1){
			printf("socket accept error\n");
			close(fd_sock);
			return -1;
		}

		pid_t pid = fork();
		if(pid == -1){
			printf("fork fail\n");
			close(fd_sock);
			return -1;
		}
		else if(pid>0){
			//parent
			//close client socket for listening 
			close(cli_sock);
		}
		else if(pid==0){
			//child
			//close parent socket to dedicate to communication
			close(fd_sock);

			struct ecall_val eval;
			size_t temp = 0;
			memset(&eval, 0 ,sizeof(eval));

			len= read(cli_sock, &eval, sizeof(eval));
			printf("THIS IS FROM MAIN: \n");
			print_ecall(&eval);	
			if(len <=0){
				printf("read fail\n");
				close(cli_sock);
				exit(1);
			}

			if(eval.type == 1){
//				printf("scket_ecall_offset\n");
				temp =socket_ecall_offset();
				printf("ecall_fin\n");
				if(len<0){
					printf("ecall_offset_fail\n");
					close(cli_sock);
					exit(1);
				}
				eval.malicious_x = temp;
				print_ecall(&eval);
				len=write(cli_sock, &eval, sizeof(eval));
				if(len<0){
					printf("ecall_offset_fail\n");
					close(cli_sock);
					exit(1);
					return -1;
				}
				close(cli_sock);
				exit(1);
			}
			else if(eval.type == 2){
//				printf("socket_ecall_victim_fucntion\n");
				socket_ecall_victim_function(&eval);
print_ecall(&eval);
				len=write(cli_sock, &eval, sizeof(eval));
				if(len<0){
					printf("ecall_victim_fail\n");
					close(cli_sock);
					exit(1);
					return -1;
				}
				close(cli_sock);
				exit(1);
			}
		}
	}
	close(fd_sock);
	return 0;
}

/* Application entry */
int main(int argc, char *argv[])
{
    /* Initialize the enclave */
    initialize_enclave();
   printf("global_eid : %ld\n",global_eid); 
    /* Call the main attack function*/
    socket_init(1732);//TODO 

    /* Destroy the enclave */
	 destroy_enclave();

    return 0;
}

