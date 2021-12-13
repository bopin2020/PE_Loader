#pragma once
#include<windows.h>

//dos_header
const DWORD position_e_magic = 0x00000000;
const DWORD position_e_lfanew = 0x0000003c;

//size_of_signature
const DWORD size_of_signature = 0x00000004;

//file_header
const DWORD position_number_of_section = 0x000000fe;
const DWORD position_size_of_optional_header = 0x0000010c;

//size_of_file_header
const DWORD size_of_file_header = 0x00000014;

//optional_header
const DWORD position_address_of_entry_point = 0x00000120;
const DWORD position_image_base = 0x00000128;
const DWORD position_section_alignement = 0x00000130;
const DWORD position_file_alignment = 0x00000134;
const DWORD position_size_of_image = 0x00000148;
const DWORD position_size_of_headers = 0x0000014c;
const DWORD position_check_sum = 0x00000150;

//offset_section_header
const DWORD offset_byte_name = 0x00000000;
const DWORD offset_virtual_size = 0x00000008;
const DWORD offset_virtual_address = 0x0000000c;
const DWORD offset_size_of_raw_data = 0x00000010;
const DWORD offset_section_header = 0x00000028;