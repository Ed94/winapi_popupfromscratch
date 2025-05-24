package zydis

import "core:c"

foreign import zydis "lib/zydis.lib"

// Basic types
ZyanStatus :: c.uint32_t
ZYAN_STATUS_SUCCESS :: 0

// Machine modes
Machine_Mode :: enum c.uint8_t {
	LONG_64 = 0,
	LONG_COMPAT_32,
	LONG_COMPAT_16,
	LEGACY_32,
	LEGACY_16,
	REAL_16,
}

// Mnemonics - only the ones you're using
Mnemonic :: enum c.uint16_t {
	INVALID = 0,
	ADD     = 10,
	CALL    = 89,
	MOV     = 525,
	POP     = 648,
	PUSH    = 673,
	RET     = 799,
	SUB     = 1057,
	XOR     = 1295,
}

// Registers - only the ones you're using
Register :: enum c.uint8_t {
	NONE = 0,
	RAX  = 57,
	RCX  = 58,
	RDX  = 59,
	RBX  = 60,
	RSP  = 61,
	RBP  = 62,
	RSI  = 63,
	RDI  = 64,
	R8   = 65,
	R9   = 66,
	R10  = 67,
	R11  = 68,
}

// Operand types
Operand_Type :: enum c.uint8_t {
	UNUSED = 0,
	REGISTER,
	MEMORY,
	POINTER,
	IMMEDIATE,
}

// Encoder structures
Encoder_Operand :: struct {
	type: Operand_Type,
	reg: struct {
		value: Register,
		is4  : bool,
	},
	mem: struct {
		base        : Register,
		index       : Register,
		scale       : c.uint8_t,
		displacement: c.int64_t,
		size        : c.uint16_t,
	},
	ptr: struct {
		segment: c.uint16_t,
		offset : c.uint32_t,
	},
	imm: struct {
		u: c.uint64_t,
		s: c.int64_t,
	},
}

Encoder_Request :: struct {
	machine_mode     : Machine_Mode,
	allowed_encodings: c.uint32_t,
	mnemonic         : Mnemonic,
	prefixes         : c.uint64_t,
	branch_type      : c.uint8_t,
	branch_width     : c.uint8_t,
	address_size_hint: c.uint8_t,
	operand_size_hint: c.uint8_t,
	operand_count    : c.uint8_t,
	operands         : [5]Encoder_Operand,
	evex: struct {
		broadcast   : c.uint8_t,
		rounding    : c.uint8_t,
		sae         : bool,
		zeroing_mask: bool,
	},
	mvex: struct {
		broadcast    : c.uint8_t,
		conversion   : c.uint8_t,
		rounding     : c.uint8_t,
		swizzle      : c.uint8_t,
		sae          : bool,
		eviction_hint: bool,
	},
}

@(default_calling_convention="c", link_prefix="Zydis")
foreign zydis {
	EncoderEncodeInstruction :: proc(request: ^Encoder_Request, buffer: rawptr, length: ^c.size_t) -> ZyanStatus ---
	EncoderNopFill           :: proc(buffer: rawptr, length: c.size_t) -> ZyanStatus ---
}
