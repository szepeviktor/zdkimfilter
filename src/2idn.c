#include <stdio.h>
#include <stdlib.h>
#include <idn2.h>

// heck, what's the inverse of idn2 -l?
int main(int argc, char*argv[])
{
	for (int i = 1; i < argc; ++i)
	{
		char *out = NULL;
		if (idn2_to_unicode_8z8z(argv[i], &out, 0) == IDN2_OK)
			puts(out);
		else
			fprintf(stderr, "%s: failed to convert %s\n", argv[0], argv[i]);
		free(out);
	}
}
