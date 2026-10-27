#ifndef NM_CAMERA_XML_H
#define NM_CAMERA_XML_H
#include <stdbool.h>
#include <stddef.h>
/* Bounded XML subset for ONVIF. No DTD/external entities. Validates the entire
 * document before returning any value. Namespace prefixes are ignored only
 * when selecting a value; nesting compares full qualified names. */
bool nm_camera_xml_value(const char *xml, const char *local, const char *attribute, unsigned index,
                         char *out, size_t capacity);
bool nm_camera_xml_escape(const char *, char *, size_t);
#endif
