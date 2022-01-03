#pragma once
#include<windows.h>

size_t get_section_images_buffer(DWORD file_buffer_size, DWORD section_alignment) {

	size_t image_part_size = 0;
	DWORD mod_value = file_buffer_size % section_alignment;

	if (mod_value == 0) {
		return file_buffer_size;
	}

	if (mod_value == file_buffer_size) {
		return section_alignment;
	}

	return ((file_buffer_size / section_alignment) + 1) * section_alignment;
}