//Socket structures 
typedef struct ecall_val{
	int type; // if 1 == ecall_offset, if 2 == ecall_victim
	size_t x;
	uint8_t* array2;
	unsigned int* array1_size;
	size_t malicious_x;
}ecall_val;


