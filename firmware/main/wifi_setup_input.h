#ifndef NM_WIFI_SETUP_INPUT_H
#define NM_WIFI_SETUP_INPUT_H
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

typedef struct { char text[65]; size_t used; bool overflow, skip_lf; } nm_wifi_input;
/* One bounded, non-echoed line; reject controls, drain overflow, support CRLF. */
static inline int nm_wifi_input_feed(nm_wifi_input *s,unsigned char c)
{
    if (s->skip_lf) { s->skip_lf=false; if (c=='\n') return 0; }
    if (c=='\r' || c=='\n') {
        s->skip_lf=c=='\r'; s->text[s->used]=0;
        int result=s->overflow ? -1 : 1;
        s->used=0; s->overflow=false; return result;
    }
    if ((c==8 || c==127) && !s->overflow) {
        if (s->used) s->text[--s->used]=0;
        return 0;
    }
    if (c<32 || s->used>=sizeof(s->text)-1) s->overflow=true;
    else if (!s->overflow) s->text[s->used++]=(char)c;
    return 0;
}
static inline bool nm_wifi_input_valid(const char *text,bool password)
{
    size_t length=strlen(text);
    return password ? length>=8 && length<=63 : length>=1 && length<=32;
}
#endif
