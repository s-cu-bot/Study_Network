#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <netinet/in.h>
#include "add-nbo.h"

int main(int argc, char* argv[]) {

	FILE *fp1 = fopen(argv[1], "rb");
	if( fp1 == NULL ) {
		printf("%s 파일을 열 수 없습니다!",argv[1]);
		return 0;
	}

	FILE *fp2 = fopen(argv[2], "rb");
	if( fp2 == NULL ) {
		printf("%s 파일을 열 수 없습니다!",argv[2]);
		return 0;
	}


	uint32_t *input_1; //첫번째 binary 파일 값을 저장
	uint32_t *input_2; //두번째 binary 파일 값을 저장

	input_1 = (uint32_t *)malloc(sizeof(argv[1])*sizeof(uint32_t));
	input_2 = (uint32_t *)malloc(sizeof(argv[2])*sizeof(uint32_t));

	fread(input_1, sizeof(uint32_t), 1, fp1);
	fread(input_2, sizeof(uint32_t), 1, fp2);

	input_1[0] = htonl(input_1[0]);
	input_2[0] = htonl(input_2[0]);

	uint32_t input_3 = add_nbo(input_1[0], input_2[0]);

	printf("%d(0x%x) + %d(0x%x) = %d(0x%x)\n", input_1[0], input_1[0], input_2[0], input_2[0], input_3, input_3);

	free(input_1);
	free(input_2);

	fclose(fp2);
	fclose(fp1);
}
