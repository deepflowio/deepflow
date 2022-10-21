/*
 * file: tools/ebpftobuffer.c
 *
 * This tool is used to convert eBPF bytecode into a buffer in C file.
 *
 * Uage: ebpftobuffer <ebpf-elf-file> <target-file> <variable-name>
 * @ebpf-elf-file : eBPF binary file path (to be converted)
 * @target-file : target c file path
 * @variable-name : buffer variable name
 */

#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <malloc.h>
#include <unistd.h>

static unsigned char *read_bin_file(char *name, int *len)
{
	FILE *file;
	unsigned char *buffer;
	unsigned long file_len;

	//Open file
	file = fopen(name, "rb");
	if (!file) {
		fprintf(stderr, "Unable to open file %s", name);
		return NULL;
	}
	//Get file length
	fseek(file, 0, SEEK_END);
	file_len = ftell(file);
	fseek(file, 0, SEEK_SET);

	//Allocate memory
	buffer = (char *)malloc(file_len + 1);
	if (!buffer) {
		fprintf(stderr, "Memory error!");
		fclose(file);
		return NULL;
	}
	//Read file contents into buffer
	fread(buffer, file_len, 1, file);
	fclose(file);
	//Do what ever with buffer
	*len = file_len;
	return buffer;
}

int main(int argc, char *argv[])
{
	if (argc < 4) {
		printf("Uage:%s <ebpf-elf-file> <target-file> <variable-name>\n",
		       argv[0]);
		return -1;
	}
	char *ebpf_elf_file = argv[1];
	char *target_file = argv[2];
	char *variable_name = argv[3];

	int len = 0;
	unsigned char *data =
	    read_bin_file(ebpf_elf_file, &len);
	if (len <= 0 || data == NULL) {
		fprintf(stderr, "Unable to read file %s", argv[1]);
		if (data != NULL)
			free(data);
		return -1;

	}

	char data_buf[1024];
	remove(target_file);
	int target_fd = open(target_file, O_RDWR | O_CREAT | O_APPEND, 0777);
	if (target_fd == -1) {
		fprintf(stderr, "open(%s) failed.\n", target_file);
		return -1;
	}
	snprintf(data_buf, sizeof(data_buf), "static unsigned char %s[] = \"",
		 variable_name);
	int data_len = strlen(data_buf);
	if (write(target_fd, data_buf, data_len) != data_len) {
		fprintf(stderr, "Error writing to the file.\n");
		return -1;
	}
	int i;
	for (i = 0; i < len; i++) {
		snprintf(data_buf, sizeof(data_buf), "\\x%02x", data[i]);
		data_len = strlen(data_buf);
		if (write(target_fd, data_buf, data_len) != data_len) {
			fprintf(stderr, "Error writing to the file.\n");
			return -1;
		}
	}

	write(target_fd, "\";\n", 3);
	close(target_fd);
	free(data);
	return 0;
}
