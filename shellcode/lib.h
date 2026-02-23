/*
 *	Minimalistic library for shellcodes
 */

#define ISNUM(a) ((a) >= '0' && (a) <= '9')
#define ISHEX(a) (ISNUM(a) || (a) >= 'A' && (a) <= 'F' || (a) >= 'a' && (a) <= 'f')
#define ISLOWER(a) ((a) >= 'a' && (a) <= 'z')
#define ISUPPER(a) ((a) >= 'A' && (a) <= 'Z')

// Prototypes
static long _atol(char *s);
static void _ltoa_(long input, char *buffer, int radix);
static void _lltoa_(long long input, char *buffer, int radix);
static unsigned long _atox(char *s);
static char *_strcpy(char *dest, const char *src);
static char *_strncpy(char *dest, const char *src, unsigned n);
static int _strcmp(const char *s1, const char *s2);
static int _strncmp(const char *s1, const char *s2, size_t n);
static unsigned _strlen(const char *s);
static unsigned _wcslen(const wchar_t *s);
static char *_strcat(char *dest, const char *src);
static char *_strchr(const char *s, int c);
static char *_strrchr(const char *s, int c);
static void *_memcpy(void *dest, const void *src, unsigned n);
static void *_memmove(void *dest, const void *src, unsigned n);
static void *_memchr(const void *s, int c, unsigned n);
static void *_memrchr(const void *s, int c, unsigned n);
static void *_memset(void *s, int c, size_t n);

// Convert decimal string to long (signed), ignore errors
static long _atol(char *s)
{
	long ret = 0;
	int sign = 0;

	if (*s == '-')
	{
		sign = 1;
		++s;
	}

	while (ISNUM(*s))
	{
		ret = ret * 10ULL + (unsigned long)(*s - '0');
		++s;
	}

	if (sign)
		ret = -ret;

	return	ret;
}

static void _ltoa_(long input, char *buffer, int radix)
{
	_lltoa_(radix == 16 ? (long long)(unsigned long)input : (long long)input, buffer, radix);
}

static void _lltoa_(long long input, char *buffer, int radix)
{
	int sign = 0;
	char tmp[32];
	int i;

	if (input < 0 && radix == 10)
	{
		sign = 1;
		input = -input;
	}

	if (!input)
	{
ret_0:
		buffer[0] = '0';
		buffer[1] = '\0';
		return;
	}

	switch (radix)
	{
	default:
		goto	ret_0;

	case 10:
		for (i = 0; input; ++i)
		{
			tmp[i] = input % 10 + '0';
			input /= 10;
		}
		while (i--)
			*buffer++ = tmp[i];
		*buffer = '\0';
		break;
			
	case 16:
		for (i = 15; i >= 0; --i, input = (unsigned long long)input >> 4)
		{
			buffer[i] = (char)(input & 0xF);
			if (buffer[i] < 10)
				buffer[i] += '0';
			else
				buffer[i] += 'A' - 10;
		}
		buffer[16] = '\0';
		break;
	}
}

// Convert decimal string to hex long (unsigned), ignore errors
static unsigned long _atox(char *s)
{
	unsigned long ret = 0;

	while (ISHEX(*s))
	{
		if (ISNUM(*s))
			ret = (ret << 4) + (unsigned long)(*s - '0');
		else if (ISLOWER(*s))
			ret = (ret << 4) + (unsigned long)(*s - 'a' + 10);
		else
			ret = (ret << 4) + (unsigned long)(*s - 'A' + 10);
		++s;
	}

	return	ret;
}

static char *_strcpy(char *dest, const char *src)
{
	char *ret = dest;

	if (!ret)
		goto	to_ret;

	do
		*dest++ = *src;
	while (*src++);

to_ret:
	return	ret;
}

static char *_strncpy(char *dest, const char *src, unsigned n)
{
	char *ret = dest;

	if (!ret)
		goto	to_ret;

	do
		*dest++ = *src;
	while (*src++ && --n);

to_ret:
	return	ret;
}

static int _strcmp(const char *s1, const char *s2)
{
	int ret = 0;

	if (!s1 && !s2)
		return	0;
	else if (!s1)
		return	-1;
	else if (!s2)
		return	1;

	while (*s1 && *s2)
		ret = *s1++ - *s2++;

	return	ret;
}

static int _strncmp(const char *s1, const char *s2, size_t n)
{
	int ret = 0;

	if (!s1 && !s2)
		return	0;
	else if (!s1)
		return	-1;
	else if (!s2)
		return	1;

	while (*s1 && *s2 && --n)
		ret = *s1++ - *s2++;

	return	ret;
}

static unsigned _strlen(const char *s)
{
	unsigned ret = 0;

	while (*s++)
		++ret;

	return	ret;
}

static unsigned _wcslen(const wchar_t *s)
{
	unsigned ret = 0;

	while (*s++)
		++ret;

	return	ret;
}


static char *_strcat(char *dest, const char *src)
{
	char *ret = dest;
	unsigned n = _strlen(dest);

	_strcpy(dest + n, src);
	return	ret;
}

static char *_strchr(const char *s, int c)
{
	do
		if ((int)*s == c)
			return	(char*)s;
	while (*s++);

	if (!c)
		return	(char*)s;
	return	NULL;
}

static char *_strrchr(const char *s, int c)
{
	unsigned n = _strlen(s);

	do
		if ((int)*(s + n) == c)
			return	(char*)s + n;
	while (n--);

	return	NULL;
}

static void *_memcpy(void *dest, const void *src, unsigned n)
{
	while (n--)
		((char*)dest)[n] = ((char*)src)[n];

	return	dest;
}

static void *_memmove(void *dest, const void *src, unsigned n)
{
	char *d = dest;
	const char *s = src;

	while (n--)
	{
		if ((char*)dest - (char*)src < 0)
			((char*)dest)[n] = ((char*)src)[n];
		else
			(((char*)dest)++)[0] = (((char*)src)++)[0];
	}

	return	dest;
}

static void *_memchr(const void *s, int c, unsigned n)
{
	do
		if ((int)*((char*)s)++ == c)
			return	(char*)s - 1;
	while (--n);

	return	NULL;
}

static void *_memrchr(const void *s, int c, unsigned n)
{
	do
		if ((int)*((char*)s + n) == c)
			return	(char*)s + n;
	while (n--);

	return	NULL;
}

static void *_memset(void *s, int c, size_t n)
{
	
	while (n--)
		((char*)s)[n] = (char)c;

	return	s;
}


// From WRK 1.2 -- NTDEF.H

//++
//
// VOID
// InitializeObjectAttributes(
//     OUT POBJECT_ATTRIBUTES p,
//     IN PUNICODE_STRING n,
//     IN ULONG a,
//     IN HANDLE r,
//     IN PSECURITY_DESCRIPTOR s
//     )
//
//--

#define InitializeObjectAttributes( p, n, a, r, s ) { \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

// RTL_ to avoid collisions in the global namespace.
// I don't believe there are possible/likely constant RootDirectory
// or SecurityDescriptor values other than NULL, so they are hardcoded.
// As well, the string will generally be const, so we cast that away.
#define RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a) \
    { sizeof(OBJECT_ATTRIBUTES), NULL, RTL_CONST_CAST(PUNICODE_STRING)(n), a, NULL, NULL }

// This synonym is more appropriate for initializing what isn't actually const.
#define RTL_INIT_OBJECT_ATTRIBUTES(n, a) RTL_CONSTANT_OBJECT_ATTRIBUTES(n, a)


// From WRK 1.2 -- NTRTL.H

#define RtlInitEmptyUnicodeString(_ucStr,_buf,_bufSize) \
    ((_ucStr)->Buffer = (_buf), \
     (_ucStr)->Length = 0, \
     (_ucStr)->MaximumLength = (USHORT)(_bufSize))


// From WRK 1.2 -- NTIOAPI.H

//
// Define special ByteOffset parameters for read and write operations
//

#define FILE_WRITE_TO_END_OF_FILE       0xffffffff
#define FILE_USE_FILE_POINTER_POSITION  0xfffffffe
