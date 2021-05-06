
extern "C"
{
//void *memcpy(void *dst, const void *src, size_t size);
//void *memset(void *mem, unsigned char val, size_t size);
}

int str_item_count(char *str, char sep);
BOOL str_item_get(char *str, char sep, int num, char **buff);
