#include <stdio.h>

int fn1()
{
	int a = 10;
	printf("hello from fn1, %d\n", a);
	return a;
}

int fn2()
{
	int b = 9;
	printf("hello from fn2, %d\n", b);
	return b;
}

int main()
{
	puts("hi");
	fn1();
	fn2();
}
