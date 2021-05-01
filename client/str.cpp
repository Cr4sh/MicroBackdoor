#include "stdafx.h"
//--------------------------------------------------------------------------------------
int str_item_count(char *str, char sep)
{
    int count = 1;

    if (str == NULL)
    {
        return 0;
    }    

    if (str == NULL)
    {
        return 0;
    }

    for (size_t i = 0; i < strlen(str); i++)
    {
        if (str[i] == sep)
        {
            count += 1;
        }
    }

    return count;
}
//--------------------------------------------------------------------------------------
BOOL str_item_get(char *str, char sep, int num, char **buff)
{
    BOOL found = FALSE;

    if (str == NULL || buff == NULL)
    {
        return FALSE;
    }
    
    char *tmp = str;
    size_t i = 0, n = 0, src_len = strlen(str);

    for (i = 0; i <= src_len; i++)
    {
        if (str[i] == sep || i == src_len)
        {
            if (n == num)
            {
                found = TRUE;
                break;
            }

            tmp = str + i + 1;
            n++;
        }
    }

    if (found)
    {
        int len = (int)(i - (tmp - str));

        if (*buff = (char *)M_ALLOC(len + 1))
        {
            memset(*buff, 0, len + 1);
            memcpy(*buff, tmp, len);
        }
        else
        {
            return FALSE;
        }
    }

    return found;
}
//--------------------------------------------------------------------------------------
// EoF
