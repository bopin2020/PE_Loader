#pragma once
#include<windows.h>
#include<fstream>

DWORD get_offset_optional_header();

size_t get_section_images_buffer(DWORD file_buffer_size, DWORD section_alignment);