package pe

import bytes   "core:bytes"
import mem     "core:mem"
import slice   "core:slice"
import strings "core:strings"
import unicode "core:unicode"
import utf8    "core:unicode/utf8"
import utf16   "core:unicode/utf16"
import core_pe "core:debug/pe"
	COFF_Symbol                 :: core_pe.COFF_Symbol
	COFF_Symbol_Aux_Format5     :: core_pe.COFF_Symbol_Aux_Format5
	Data_Directory              :: core_pe.Data_Directory
	Debug_Directory_Entry       :: core_pe.Debug_Directory_Entry
	File_Header                 :: core_pe.File_Header
	IMAGE_COMDAT_SELECT         :: core_pe.IMAGE_COMDAT_SELECT
	IMAGE_DEBUG_TYPE            :: core_pe.IMAGE_DEBUG_TYPE
	IMAGE_DIRECTORY_ENTRY       :: core_pe.IMAGE_DIRECTORY_ENTRY
	IMAGE_DLLCHARACTERISTIC     :: core_pe.IMAGE_DLLCHARACTERISTIC
	IMAGE_DLLCHARACTERISTICS    :: core_pe.IMAGE_DLLCHARACTERISTICS
	IMAGE_FILE_CHARACTERISTIC   :: core_pe.IMAGE_FILE_CHARACTERISTIC
	IMAGE_FILE_CHARACTERISTICS  :: core_pe.IMAGE_FILE_CHARACTERISTICS
	IMAGE_FILE_MACHINE          :: core_pe.IMAGE_FILE_MACHINE
	IMAGE_REL                   :: core_pe.IMAGE_REL
	// IMAGE_SCN_CHARACTERISTICS   :: core_pe.IMAGE_SCN_CHARACTERISTICS
	IMAGE_SCN_CHARACTERISTICS :: distinct bit_set[IMAGE_SCN_CHARACTERISTIC; u32le]
	IMAGE_SCN_CHARACTERISTIC :: enum u32le {
			TYPE_NO_PAD            = 3,  // 0x00000008
			CNT_CODE               = 5,  // 0x00000020
			CNT_INITIALIZED_DATA   = 6,  // 0x00000040
			CNT_UNINITIALIZED_DATA = 7,  // 0x00000080
			LNK_OTHER              = 8,  // 0x00000100
			LNK_INFO               = 9,  // 0x00000200
			LNK_REMOVE             = 11, // 0x00000800
			LNK_COMDAT             = 12, // 0x00001000
			GPREL                  = 15, // 0x00008000
			MEM_PURGEABLE          = 17, // 0x00020000
			MEM_16BIT              = 17, // 0x00020000 (same as MEM_PURGEABLE)
			MEM_LOCKED             = 18, // 0x00040000
			MEM_PRELOAD            = 19, // 0x00080000
			// Alignment bits (20-23) handled separately
			ALIGN_BIT_20           = 20, // Used for alignment encoding
			ALIGN_BIT_21           = 21, // Used for alignment encoding
			ALIGN_BIT_22           = 22, // Used for alignment encoding
			ALIGN_BIT_23           = 23, // Used for alignment encoding
			LNK_NRELOC_OVFL        = 24, // 0x01000000
			MEM_DISCARDABLE        = 25, // 0x02000000
			MEM_NOT_CACHED         = 26, // 0x04000000
			MEM_NOT_PAGED          = 27, // 0x08000000
			MEM_SHARED             = 28, // 0x10000000
			MEM_EXECUTE            = 29, // 0x20000000
			MEM_READ               = 30, // 0x40000000
			MEM_WRITE              = 31, // 0x80000000
	}
	// Alignment constants using the bit_set type
	IMAGE_SCN_ALIGN_1BYTES    :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_20}                               // 0x00100000
	IMAGE_SCN_ALIGN_2BYTES    :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_21}                               // 0x00200000
	IMAGE_SCN_ALIGN_4BYTES    :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_20, .ALIGN_BIT_21}                // 0x00300000
	IMAGE_SCN_ALIGN_8BYTES    :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_22}                               // 0x00400000
	IMAGE_SCN_ALIGN_16BYTES   :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_20, .ALIGN_BIT_22}                // 0x00500000
	IMAGE_SCN_ALIGN_32BYTES   :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_21, .ALIGN_BIT_22}                // 0x00600000
	IMAGE_SCN_ALIGN_64BYTES   :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_20, .ALIGN_BIT_21, .ALIGN_BIT_22} // 0x00700000
	IMAGE_SCN_ALIGN_128BYTES  :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_23}                               // 0x00800000
	IMAGE_SCN_ALIGN_256BYTES  :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_20, .ALIGN_BIT_23}                // 0x00900000
	IMAGE_SCN_ALIGN_512BYTES  :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_21, .ALIGN_BIT_23}                // 0x00A00000
	IMAGE_SCN_ALIGN_1024BYTES :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_20, .ALIGN_BIT_21, .ALIGN_BIT_23} // 0x00B00000
	IMAGE_SCN_ALIGN_2048BYTES :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_22, .ALIGN_BIT_23}                // 0x00C00000
	IMAGE_SCN_ALIGN_4096BYTES :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_20, .ALIGN_BIT_22, .ALIGN_BIT_23} // 0x00D00000
	IMAGE_SCN_ALIGN_8192BYTES :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_21, .ALIGN_BIT_22, .ALIGN_BIT_23} // 0x00E00000
	// Mask for clearing alignment bits before setting new alignment
	IMAGE_SCN_ALIGN_MASK :: IMAGE_SCN_CHARACTERISTICS{.ALIGN_BIT_20, .ALIGN_BIT_21, .ALIGN_BIT_22, .ALIGN_BIT_23} // 0x00F00000
	IMAGE_SUBSYSTEM             :: core_pe.IMAGE_SUBSYSTEM
	IMAGE_SYM_ABSOLUTE          :: core_pe.IMAGE_SYM_ABSOLUTE
	IMAGE_SYM_CLASS             :: core_pe.IMAGE_SYM_CLASS
	IMAGE_SYM_DEBUG             :: core_pe.IMAGE_SYM_DEBUG
	IMAGE_SYM_TYPE              :: core_pe.IMAGE_SYM_TYPE
	IMAGE_SYM_UNDEFINED         :: core_pe.IMAGE_SYM_UNDEFINED
	OPTIONAL_HEADER_MAGIC       :: core_pe.OPTIONAL_HEADER_MAGIC
	Optional_Header32           :: core_pe.Optional_Header32
	Optional_Header64           :: core_pe.Optional_Header64
	Optional_Header_Base        :: core_pe.Optional_Header_Base
	PE_CODE_VIEW_SIGNATURE_RSDS :: core_pe.PE_CODE_VIEW_SIGNATURE_RSDS
	Reloc                       :: core_pe.Reloc
	// Section_Header32            :: core_pe.Section_Header32
	Section_Header32 :: struct {
		name:                    [8]u8,
		virtual_size:            u32le,
		virtual_address:         u32le,
		size_of_raw_data:        u32le,
		pointer_to_raw_data:     u32le,
		pointer_to_relocations:  u32le,
		pointer_to_line_numbers: u32le,
		number_of_relocations:   u16le,
		number_of_line_numbers:  u16le,
		characteristics:         IMAGE_SCN_CHARACTERISTICS,
	}

// Import structures
Import_Descriptor :: struct #packed {
	original_first_thunk: u32le,  // RVA to import lookup table
	time_date_stamp     : u32le,  // 0 if not bound
	forwarder_chain     : u32le,  // -1 if no forwarders
	name                : u32le,  // RVA to ASCII DLL name
	first_thunk         : u32le,  // RVA to import address table
}

Import_By_Name :: struct #packed {
	hint: u16le,
	name: [1]u8,  // Variable length, null-terminated
}

Import_Info :: struct {
	dll_name : string,
	functions: [dynamic]string,
}

DOS_Header :: struct #packed {
	magic                    : u16le,
	bytes_on_last_page       : u16le,
	pages_in_file            : u16le,
	relocations              : u16le,
	size_of_header_paragraphs: u16le,
	min_extra_paragraphs     : u16le,
	max_extra_paragraphs     : u16le,
	initial_ss               : u16le,
	initial_sp               : u16le,
	checksum                 : u16le,
	initial_ip               : u16le,
	initial_cs               : u16le,
	addr_relocation_table    : u16le,
	overlay_number           : u16le,
	reserved                 : [4]u16le,
	oem_identifier           : u16le,
	oem_information          : u16le,
	reserved2                : [10]u16le,
	addr_new_exe_header      : u32le,
}

NT_Headers64 :: struct #packed {
	signature      : u32le,
	file_header    : File_Header,
	optional_header: Optional_Header64,
}

// PE encoding context
PE_Context :: struct {
	allocator: mem.Allocator,

	buf_utf16 : [dynamic]u16,
	strings   : map[string]u32,
	
	// Headers
	dos_header: DOS_Header,
	nt_headers: NT_Headers64,
	sections  : [dynamic]Section_Header32,
	
	// Section data
	text_data : [dynamic]byte,
	data_data : [dynamic]byte,
	rdata_data: [dynamic]byte,
	idata_data: [dynamic]byte,
	
	// Import data
	imports: [dynamic]Import_Info,
	
	// File alignment requirements
	file_alignment   : u32,
	section_alignment: u32,
}

// Initialize PE context with default values
init_context :: proc(ctx: ^PE_Context, allocator: mem.Allocator)
{
	ctx.allocator = allocator
	ctx.buf_utf16 = make([dynamic]u16, mem.Kilobyte * 32, mem.Kilobyte * 32, allocator)
	ctx.imports   = make([dynamic]Import_Info, 0, 128, allocator)
	ctx.strings   = make(map[string]u32, 128, allocator)

	ctx.sections   = make([dynamic]Section_Header32, 0, 128, allocator)
	ctx.text_data  = make([dynamic]byte, 0, mem.Kilobyte * 32, allocator)
	ctx.data_data  = make([dynamic]byte, 0, mem.Kilobyte * 32, allocator)
	ctx.rdata_data = make([dynamic]byte, 0, mem.Kilobyte * 32, allocator)
	ctx.idata_data = make([dynamic]byte, 0, mem.Kilobyte * 32, allocator)

	// Initialize DOS header
	{
		using ctx.dos_header;
		magic                     = 0x5A4D  // "MZ"
		bytes_on_last_page        = 0x90
		pages_in_file             = 0x03
		size_of_header_paragraphs = 0x04
		min_extra_paragraphs      = 0x00
		max_extra_paragraphs      = 0xFFFF
		initial_ss                = 0x00
		initial_sp                = 0xB8
		addr_new_exe_header       = 0x40  // PE header starts at 0x40
	}
	// Initialize NT headers
	{
		using ctx.nt_headers
		signature = 0x00004550  // "PE\0\0"
		// File header
		file_header.machine                 = .AMD64
		file_header.number_of_sections      = 0  // Will be updated
		file_header.time_date_stamp         = 0
		file_header.pointer_to_symbol_table = 0
		file_header.number_of_symbols       = 0
		file_header.size_of_optional_header = size_of(Optional_Header64)
		file_header.characteristics         = {.EXECUTABLE_IMAGE, .LARGE_ADDRESS_AWARE}
		// Optional header
		optional_header.magic                          = .PE32_PLUS
		optional_header.major_linker_version           = 14
		optional_header.minor_linker_version           = 0
		optional_header.size_of_code                   = 0  // Will be updated
		optional_header.size_of_initialized_data       = 0  // Will be updated
		optional_header.size_of_uninitialized_data     = 0
		optional_header.address_of_entry_point         = 0  // Will be updated
		optional_header.base_of_code                   = 0x1000
		optional_header.image_base                     = 0x140000000
		optional_header.section_alignment              = cast(u32le)ctx.section_alignment
		optional_header.file_alignment                 = cast(u32le)ctx.file_alignment
		optional_header.major_operating_system_version = 6
		optional_header.minor_operating_system_version = 0
		optional_header.major_image_version            = 0
		optional_header.minor_image_version            = 0
		optional_header.major_subsystem_version        = 6
		optional_header.minor_subsystem_version        = 0
		optional_header.win32_version_value            = 0
		optional_header.size_of_image                  = 0  // Will be updated
		optional_header.size_of_headers                = 0  // Will be updated
		optional_header.check_sum                      = 0
		optional_header.subsystem                      = .WINDOWS_CUI  // Console app by default
		optional_header.dll_characteristics            = {.NX_COMPAT, .TERMINAL_SERVER_AWARE}
		optional_header.size_of_stack_reserve          = 0x100000
		optional_header.size_of_stack_commit           = 0x1000
		optional_header.size_of_heap_reserve           = 0x100000
		optional_header.size_of_heap_commit            = 0x1000
		optional_header.loader_flags                   = 0
		optional_header.number_of_rva_and_sizes        = 16
	}
	ctx.file_alignment    = 0x200   // 512 bytes
	ctx.section_alignment = 0x1000  // 4096 bytes
}

// Add import for a DLL
add_import :: proc(ctx: ^PE_Context, dll_name: string, function_name: string)
{
	// Find existing import or create new one
	for & import_info in ctx.imports {
		if import_info.dll_name == dll_name {
			append(& import_info.functions, function_name)
			return
		}
	}
	// Create new import
	import_info := Import_Info{
		dll_name  = dll_name,
		functions = make([dynamic]string, 0, 128, ctx.allocator),
	}
	append(& import_info.functions, function_name)
	append(& ctx.imports, import_info)
}

// Add string data to .rdata section and return RVA
add_string_data :: proc(ctx: ^PE_Context, data: []byte) -> u32 {
	rva := cast(u32)len(ctx.rdata_data)
	append(& ctx.rdata_data, ..data)
	return rva
}

// Convert UTF-8 string to UTF-16 and add to .rdata
add_utf16_string :: proc(ctx: ^PE_Context, str: string) -> u32
{
	// Reserve buffer for UTF-16 conversion (worst case: 2x string length)
	clear(& ctx.buf_utf16)
	resize(& ctx.buf_utf16, len(str) * 2)
	// Convert UTF-8 to UTF-16
	encoded_len := utf16.encode_string(ctx.buf_utf16[:], str)
	rva         := cast(u32)len(ctx.rdata_data)
	// Convert UTF-16 data to bytes with little-endian ordering
	for idx in 0 ..< encoded_len {
		code_unit := ctx.buf_utf16[idx]
		bytes_le  := [2]byte{cast(u8)(code_unit & 0xFF), cast(u8)(code_unit >> 8)}
		append(& ctx.rdata_data, .. bytes_le[:])
	}
	// Add null terminator (UTF-16 null is 2 bytes)
	append(& ctx.rdata_data, 0, 0)
	return rva
}

// Add code section with machine code
add_code_section :: proc(ctx: ^PE_Context, code: []byte, entry_point_offset: u32 = 0) {
	append(& ctx.text_data, .. code)
	section: Section_Header32
	copy(section.name[:], ".text")
	section.virtual_size            = cast(u32le)len(code)
	section.virtual_address         = 0x1000  // Standard .text RVA
	section.size_of_raw_data        = cast(u32le) align_up(cast(u32) len(code), ctx.file_alignment)
	section.pointer_to_raw_data     = 0  // Will be calculated later
	section.pointer_to_relocations  = 0
	section.pointer_to_line_numbers = 0
	section.number_of_relocations   = 0
	section.number_of_line_numbers  = 0
	section.characteristics         = {.CNT_CODE, .MEM_EXECUTE, .MEM_READ}
	append(& ctx.sections, section)
	// Update entry point
	ctx.nt_headers.optional_header.address_of_entry_point = cast(u32le)(0x1000 + entry_point_offset)
}

// Add .rdata section for strings and constants
add_rdata_section :: proc(ctx: ^PE_Context) {
	if len(ctx.rdata_data) == 0 do return
	section: Section_Header32
	copy(section.name[:], ".rdata")
	section.virtual_size            = cast(u32le) len(ctx.rdata_data)
	section.virtual_address         = 0  // Will be calculated later
	section.size_of_raw_data        = cast(u32le) align_up(cast(u32)len(ctx.rdata_data), ctx.file_alignment)
	section.pointer_to_raw_data     = 0  // Will be calculated later
	section.pointer_to_relocations  = 0
	section.pointer_to_line_numbers = 0
	section.number_of_relocations   = 0
	section.number_of_line_numbers  = 0
	section.characteristics         = {.CNT_INITIALIZED_DATA, .MEM_READ}
	append(&ctx.sections, section)
}

// Build import directory and import tables
build_import_tables :: proc(ctx: ^PE_Context) -> (import_dir_rva: u32, iat_rva: u32)
{
	if len(ctx.imports) == 0 do return 0, 0
	
	// Build import directory
	// TODO(Ed): This shold be just kept in the context and reused.
	import_descriptors := make([dynamic]Import_Descriptor, ctx.allocator)
	
	current_offset := cast(u32)len(ctx.idata_data)
	strings_offset := current_offset + cast(u32)((len(ctx.imports) + 1) * size_of(Import_Descriptor))
	
	iat_offset := strings_offset
	for import_info in ctx.imports
	{
		iat_offset += cast(u32)len(import_info.dll_name) + 1
		for func in import_info.functions {
			iat_offset += 2 + cast(u32)len(func) + 1 // hint + name + null
		}
	}
	iat_offset = align_up(iat_offset, 8) // Align to 8 bytes
	
	import_dir_rva = current_offset
	iat_rva        = iat_offset
	
	current_string_offset := strings_offset
	current_iat_offset    := iat_offset
	
	for import_info in ctx.imports
	{
		descriptor := Import_Descriptor {
			original_first_thunk = cast(u32le) current_iat_offset,
			time_date_stamp = 0,
			forwarder_chain = 0,
			name        = cast(u32le) current_string_offset,
			first_thunk = cast(u32le) current_iat_offset,
		}
		append(&import_descriptors, descriptor)
		current_string_offset += cast(u32)len(import_info.dll_name) + 1
		current_iat_offset    += cast(u32)(len(import_info.functions) + 1) * 8 // 8 bytes per thunk + null terminator
	}
	
	// Null terminator for import directory
	null_descriptor := Import_Descriptor{}
	append(&import_descriptors, null_descriptor)
	
	// Write import descriptors
	descriptors_bytes := slice.reinterpret([]byte, import_descriptors[:])
	append(&ctx.idata_data, ..descriptors_bytes)
	
	// Write DLL names and function names
	for import_info in ctx.imports {
		dll_name_bytes := transmute([]byte)import_info.dll_name
		append(&ctx.idata_data, ..dll_name_bytes)
		append(&ctx.idata_data, 0) // Null terminator
		
		for func in import_info.functions {
			append(&ctx.idata_data, 0, 0) // Hint (2 bytes)
			func_name_bytes := transmute([]byte)func
			append(&ctx.idata_data, ..func_name_bytes)
			append(&ctx.idata_data, 0) // Null terminator
		}
	}
	
	// Align to 8 bytes
	for len(ctx.idata_data) % 8 != 0 {
		append(&ctx.idata_data, 0)
	}
	
	// Write import address table (IAT)
	for import_info in ctx.imports
	{
		for func in import_info.functions
		{
			// Address will be filled by loader - for now put RVA to import by name
			func_name_offset := strings_offset
			for other_import, i in ctx.imports
			{
				if i >= len(ctx.imports) do break
				func_name_offset += cast(u32)len(other_import.dll_name) + 1
				if other_import.dll_name == import_info.dll_name
				{
					for other_func, j in other_import.functions {
						if other_func == func do break
						func_name_offset += 2 + cast(u32)len(other_func) + 1
					}
					break
				}
				for other_func in other_import.functions {
					func_name_offset += 2 + cast(u32)len(other_func) + 1
				}
			}
			// Write 8-byte thunk
			thunk_bytes := mem.any_to_bytes(cast(u64)func_name_offset)
			append(&ctx.idata_data, ..thunk_bytes)
		}
		// Null terminator for this DLL's thunks
		append(&ctx.idata_data, 0, 0, 0, 0, 0, 0, 0, 0)
	}

	return import_dir_rva, iat_rva
}

// Add .idata section for imports
add_idata_section :: proc(ctx: ^PE_Context) {
	if len(ctx.idata_data) == 0 do return
	section: Section_Header32
	copy(section.name[:], ".idata")
	section.virtual_size            = cast(u32le)len(ctx.idata_data)
	section.virtual_address         = 0  // Will be calculated later
	section.size_of_raw_data        = cast(u32le)align_up(cast(u32) len(ctx.idata_data), ctx.file_alignment)
	section.pointer_to_raw_data     = 0  // Will be calculated later
	section.pointer_to_relocations  = 0
	section.pointer_to_line_numbers = 0
	section.number_of_relocations   = 0
	section.number_of_line_numbers  = 0
	section.characteristics         = {.CNT_INITIALIZED_DATA, .MEM_READ, .MEM_WRITE}
	append(&ctx.sections, section)
}

// Helper to align values
align_up :: proc(value: u32, alignment: u32) -> u32 {
	return (value + alignment - 1) & ~(alignment - 1)
}

// Encode with imports support
encode :: proc(code: []byte, strs: []string, entry_point_offset: u32 = 0, 
	imports   : []Import_Info = {},
	allocator := context.allocator,
) -> []byte
{
	section_text  := ".text\x00"
	section_rdata := ".rdata\x00"
	section_idata := ".idata\x00"
	
	DOS_STUB_SIZE :: 64

	ctx: PE_Context
	init_context(& ctx, allocator)
	context.allocator = allocator
	
	// Add imports
	for import_info in imports {
		for func in import_info.functions {
			add_import(& ctx, import_info.dll_name, func)
		}
	}
	
	// Add string data
	for str in strs {
		ctx.strings[str] = add_utf16_string(& ctx, str)
	}
	
	// Add code section
	add_code_section(& ctx, code, entry_point_offset)
	
	// Add other sections
	add_rdata_section(& ctx)
	
	// Build import tables
	import_dir_rva, iat_rva := build_import_tables(&ctx)
	add_idata_section(& ctx)
	
	// Calculate header size
	headers_size := size_of(DOS_Header) + DOS_STUB_SIZE + size_of(NT_Headers64) + (len(ctx.sections)  * size_of(Section_Header32))
	
	ctx.nt_headers.optional_header.size_of_headers = cast(u32le)align_up(cast(u32)headers_size, ctx.file_alignment)
	
	// Update file header
	ctx.nt_headers.file_header.number_of_sections = cast(u16le)len(ctx.sections)
	
	// Calculate section offsets and update sizes
	current_offset := ctx.nt_headers.optional_header.size_of_headers
	current_rva    := ctx.section_alignment
	
	for & section in ctx.sections {
		section.pointer_to_raw_data = current_offset
		section.virtual_address     = cast(u32le)current_rva
		
		current_offset += section.size_of_raw_data
		current_rva    += align_up(cast(u32)section.virtual_size, ctx.section_alignment)
		
		// Update optional header sizes
		if .CNT_CODE in section.characteristics {
				ctx.nt_headers.optional_header.size_of_code += section.size_of_raw_data
		} else if .CNT_INITIALIZED_DATA in section.characteristics {
				ctx.nt_headers.optional_header.size_of_initialized_data += section.size_of_raw_data
		}
	}
	
	ctx.nt_headers.optional_header.size_of_image = cast(u32le)current_rva
	
	// Set up data directories
	if len(ctx.imports) > 0
	{
		// Find .idata section
		for & section, i in ctx.sections
		{
			if slice.equal(section.name[:7], transmute([]u8)section_idata) {
				ctx.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY.IMPORT].virtual_address = section.virtual_address + cast(u32le)import_dir_rva
				ctx.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY.IMPORT].size            = cast(u32le)((len(ctx.imports) + 1) * size_of(Import_Descriptor))
				ctx.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY.IAT].virtual_address    = section.virtual_address + cast(u32le)iat_rva
				ctx.nt_headers.optional_header.data_directory[IMAGE_DIRECTORY_ENTRY.IAT].size               = cast(u32le)(len(ctx.idata_data) - cast(int)iat_rva)
				break
			}
		}
	}
	
	// Build the final PE file
	buffer: bytes.Buffer
	bytes.buffer_init_allocator(& buffer, 0, mem.Kilobyte * 16, allocator)
	
	// Write DOS header
	bytes.buffer_write(& buffer, mem.any_to_bytes(ctx.dos_header))
	
	// Write DOS stub
	dos_stub := [64]byte{
		0x0E, 0x1F, 0xBA, 0x0E, 0x00, 0xB4, 0x09, 0xCD,
		0x21, 0xB8, 0x01, 0x4C, 0xCD, 0x21, 0x54, 0x68,
		0x69, 0x73, 0x20, 0x70, 0x72, 0x6F, 0x67, 0x72,
		0x61, 0x6D, 0x20, 0x63, 0x61, 0x6E, 0x6E, 0x6F,
		0x74, 0x20, 0x62, 0x65, 0x20, 0x72, 0x75, 0x6E,
		0x20, 0x69, 0x6E, 0x20, 0x44, 0x4F, 0x53, 0x20,
		0x6D, 0x6F, 0x64, 0x65, 0x2E, 0x0D, 0x0D, 0x0A,
		0x24, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	bytes.buffer_write(& buffer, dos_stub[:])
	
	// Write NT headers
	bytes.buffer_write(& buffer, mem.any_to_bytes(ctx.nt_headers))
	
	// Write section headers
	for section in ctx.sections {
			bytes.buffer_write(& buffer, mem.any_to_bytes(section))
	}
	
	// Pad to file alignment
	for bytes.buffer_length(& buffer) < int(ctx.nt_headers.optional_header.size_of_headers) {
			bytes.buffer_write_byte(& buffer, 0)
	}

	// Write section data in order
	for & section, id in ctx.sections
	{
		if slice.equal(section.name[:6], transmute([]u8)section_text)
		{
			bytes.buffer_write(& buffer, ctx.text_data[:])
			// Pad section
			padding := int(section.size_of_raw_data) - len(ctx.text_data)
			for pad in 0 ..< padding {
				bytes.buffer_write_byte(& buffer, 0)
			}
		}
		else if slice.equal(section.name[:7], transmute([]u8)section_rdata)
		{
			bytes.buffer_write(& buffer, ctx.rdata_data[:])
			// Pad section
			padding := int(section.size_of_raw_data) - len(ctx.rdata_data)
			for pad in 0 ..< padding {
				bytes.buffer_write_byte(& buffer, 0)
			}
		} 
		else if slice.equal(section.name[:7], transmute([]u8)section_idata)
		{
			bytes.buffer_write(& buffer, ctx.idata_data[:])
			// Pad section
			padding := int(section.size_of_raw_data) - len(ctx.idata_data)
			for pad in 0 ..< padding {
				bytes.buffer_write_byte(& buffer, 0)
			}
		}
	}
	
	return bytes.buffer_to_bytes(& buffer)
}
