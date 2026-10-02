/* Embed exactly the same read-only service file as ESP-IDF does. */
.section .rodata
.global _binary_service_hints_csv_start
.global _binary_service_hints_csv_end
_binary_service_hints_csv_start:
.incbin NM_SERVICE_HINTS_FILE
.byte 0
_binary_service_hints_csv_end:
.section .note.GNU-stack,"",%progbits
