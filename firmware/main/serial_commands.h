#ifndef NM_SERIAL_COMMANDS_H
#define NM_SERIAL_COMMANDS_H
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

typedef enum { NM_SERIAL_NONE, NM_SERIAL_PROMPT, NM_SERIAL_CONFIRM,
               NM_SERIAL_CANCEL, NM_SERIAL_HELP, NM_SERIAL_INVALID,
               NM_SERIAL_FACTORY_PROMPT, NM_SERIAL_FACTORY_CONFIRM,
               NM_SERIAL_STOP, NM_SERIAL_START } nm_serial_action;
typedef struct {
    char line[64];
    unsigned used;
    bool overflow;
    int64_t deadline;
    bool factory;
} nm_serial_parser;

static inline nm_serial_action nm_serial_feed(nm_serial_parser *s,unsigned char c,int64_t now)
{
    if (c!='\r' && c!='\n') {
        if (c<32 || c>126 || s->used>=sizeof(s->line)-1) s->overflow=true;
        else if (!s->overflow) s->line[s->used++]=(char)c;
        return NM_SERIAL_NONE;
    }
    if (!s->used && !s->overflow) return NM_SERIAL_NONE;
    s->line[s->used]=0; s->used=0;
    if (s->overflow) { s->overflow=false; s->deadline=0; return NM_SERIAL_INVALID; }
    if (!strcmp(s->line,"reregister")) {
        s->factory=false; s->deadline=now+30000000; return NM_SERIAL_PROMPT;
    }
    if (!strcmp(s->line,"factory-reset")) {
        s->factory=true; s->deadline=now+30000000; return NM_SERIAL_FACTORY_PROMPT;
    }
    bool confirmed=s->deadline && now<s->deadline &&
        !strcmp(s->line,s->factory ? "confirm factory-reset" : "confirm reregister");
    s->deadline=0;
    if (confirmed) return s->factory ? NM_SERIAL_FACTORY_CONFIRM : NM_SERIAL_CONFIRM;
    if (!strcmp(s->line,"cancel")) return NM_SERIAL_CANCEL;
    if (!strcmp(s->line,"help")) return NM_SERIAL_HELP;
    if (!strcmp(s->line,"stop")) return NM_SERIAL_STOP;
    if (!strcmp(s->line,"start")) return NM_SERIAL_START;
    return NM_SERIAL_INVALID;
}
#endif
