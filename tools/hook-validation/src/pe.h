#ifndef NSP_HOOK_VALIDATION_PE_H
#define NSP_HOOK_VALIDATION_PE_H
/* Minimal on-disk PE32+ reader for hook validation. No Windows loader involved. */
#include <stdint.h>
#include <stddef.h>
#include <wchar.h>

#define PE_MAX_SECTIONS 96
#define PE_DIR_COUNT 16
#define PE_MAX_IMAGE_BYTES (512u * 1024u * 1024u)

enum { PE_DIR_EXCEPTION = 3, PE_DIR_BASERELOC = 5 };

typedef struct {
    char name[9];
    uint32_t virtual_size;
    uint32_t virtual_address;
    uint32_t raw_size;
    uint32_t raw_pointer;
} PeSection;

typedef struct {
    uint8_t *data;
    size_t size;
    uint16_t machine;
    uint16_t optional_magic;
    uint32_t time_date_stamp;
    uint32_t size_of_image;
    uint32_t checksum;
    uint64_t image_base;
    uint16_t section_count;
    PeSection sections[PE_MAX_SECTIONS];
    uint32_t directory_count;
    uint32_t directory_rva[PE_DIR_COUNT];
    uint32_t directory_size[PE_DIR_COUNT];
} PeImage;

int pe_load(const wchar_t *path, PeImage *pe, char *err, size_t err_cap);
void pe_free(PeImage *pe);
int pe_rva_to_offset(const PeImage *pe, uint32_t rva, size_t len, size_t *offset);
const uint8_t *pe_rva_ptr(const PeImage *pe, uint32_t rva, size_t len);

#endif
