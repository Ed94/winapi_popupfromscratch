package winapi_pfs

import "core:fmt"
import os "core:os/os2"
import "core:mem"
import vmem "core:mem/virtual"
import "core:c"

import winapi "core:sys/windows"

import pe "pe"
import zydis "zydis"

winapi_popup_via_odin :: proc()
{
	winapi.MessageBoxW(nil, & winapi.utf8_to_utf16("Hello WINAPI!")[0], & winapi.utf8_to_utf16("Smol Box: VIA ODIN")[0], winapi.MB_OK)
}

// Encode a single instruction using Zydis
encode_instruction :: proc(mnemonic: zydis.Mnemonic, operands: []zydis.Encoder_Operand, allocator := context.allocator) -> []byte
{
	request := zydis.Encoder_Request{
		machine_mode  = .LONG_64,
		mnemonic      = mnemonic,
		operand_count = cast(c.uint8_t)len(operands),
	}
	for idx in 0 ..< len(operands){
		if idx < 5 {
			request.operands[idx] = operands[idx]
		}
	}
	x64_INSTRUCTION_MAX_LENGTH :: 15
	buffer: [x64_INSTRUCTION_MAX_LENGTH]byte
	length: c.size_t = x64_INSTRUCTION_MAX_LENGTH
	status := zydis.EncoderEncodeInstruction(& request, raw_data(buffer[:]), & length)
	if status != zydis.ZYAN_STATUS_SUCCESS {
		fmt.printf("Zydis encoding failed with status: %d\n", status)
		return nil
	}
	result := make([]byte, length, allocator)
	copy(result, buffer[:length])
	return result
}
// Create register operand
reg_operand :: #force_inline proc(reg: zydis.Register) -> zydis.Encoder_Operand { return zydis.Encoder_Operand { type = .REGISTER, reg = {value = reg} } }
// Create immediate operand
imm_operand :: #force_inline proc(value: u64) -> zydis.Encoder_Operand { return zydis.Encoder_Operand { type = .IMMEDIATE, imm = {u = value} } }
// Create memory operand with displacement
mem_operand :: proc(base: zydis.Register, displacement: i64) -> zydis.Encoder_Operand { 
	return zydis.Encoder_Operand{
		type = .MEMORY,
		mem = {
			base         = base,
			displacement = displacement,
			size         = 64,
		},
	}
}

winapi_popup_scratch :: proc()
{
	allocator := context.allocator
	
	// We need to:
	// 1. Set up stack frame
	// 2. Load parameters for MessageBoxW
	// 3. Call MessageBoxW
	// 4. Clean up and return
	
	// For x64 calling convention:
	// RCX = hWnd (NULL)
	// RDX = lpText 
	// R8  = lpCaption
	// R9  = uType (MB_OK = 0)
	
	// Calculate addresses - these will need to be fixed up based on actual PE layout
	text_addr       := cast(i64)0x2000 // Will be in .rdata section
	caption_addr    := cast(i64)0x2030 // Will be in .rdata section after text
	messagebox_addr := cast(i64)0x3000 // Will be in .idata section
    
	// Stage 1: Encode all instructions
	/*
	sub rsp, 40                     ; Reserve shadow space + alignment
	xor rcx, rcx                    ; hWnd = NULL
	mov rdx, [rip + text_offset]    ; lpText - we'll patch this offset
	                                ; For now, use a placeholder address
	mov r8, [rip + caption_offset]  ; lpCaption 
	xor r9, r9                      ; uType = MB_OK (0)
	call [MessageBoxW import]       ; Call MessageBoxW
	                                ; This will be a call to the import address table
	add rsp, 40                     ; Clean up stack
	ret                             ; Return
	*/

	sub_instr      := encode_instruction(.SUB, {reg_operand(.RSP), imm_operand(40)})
	xor_rcx_instr  := encode_instruction(.XOR, {reg_operand(.RCX), reg_operand(.RCX)})
	mov_rdx_instr  := encode_instruction(.MOV, {reg_operand(.RDX), imm_operand(0x140000000 + cast(u64)text_addr)})
	mov_r8_instr   := encode_instruction(.MOV, {reg_operand(.R8),  imm_operand(0x140000000 + cast(u64)caption_addr)})
	xor_r9_instr   := encode_instruction(.XOR, {reg_operand(.R9),  reg_operand(.R9)})
	mov_rax_instr  := encode_instruction(.MOV, {reg_operand(.RAX), imm_operand(0x140000000 + cast(u64)messagebox_addr)})
	call_rax_instr := encode_instruction(.CALL,{reg_operand(.RAX)})
	add_instr      := encode_instruction(.ADD, {reg_operand(.RSP), imm_operand(40)})
	ret_instr      := encode_instruction(.RET, {})
    
	// Stage 2: Validate all instructions are valid
	if	\
		sub_instr      == nil ||
		xor_rcx_instr  == nil ||
		mov_rdx_instr  == nil ||
		mov_r8_instr   == nil ||
		xor_r9_instr   == nil || 
		mov_rax_instr  == nil ||
		call_rax_instr == nil ||
		add_instr      == nil ||
		ret_instr      == nil {
			fmt.println("Failed to encode one or more instructions")
			return
	}
    
	fmt.println("All instructions encoded successfully:")
	fmt.printf("  sub rsp, 40     -> %d bytes\n", len(sub_instr))
	fmt.printf("  xor rcx, rcx    -> %d bytes\n", len(xor_rcx_instr))
	fmt.printf("  mov rdx, imm    -> %d bytes\n", len(mov_rdx_instr))
	fmt.printf("  mov r8, imm     -> %d bytes\n", len(mov_r8_instr))
	fmt.printf("  xor r9, r9      -> %d bytes\n", len(xor_r9_instr))
	fmt.printf("  mov rax, imm    -> %d bytes\n", len(mov_rax_instr))
	fmt.printf("  call rax        -> %d bytes\n", len(call_rax_instr))
	fmt.printf("  add rsp, 40     -> %d bytes\n", len(add_instr))
	fmt.printf("  ret             -> %d bytes\n", len(ret_instr))
	
	// Stage 3: Assemble all encoded instructions
	machine_code := make([dynamic]byte, allocator)
	append(& machine_code, ..sub_instr)
	append(& machine_code, ..xor_rcx_instr)
	append(& machine_code, ..mov_rdx_instr)
	append(& machine_code, ..mov_r8_instr)
	append(& machine_code, ..xor_r9_instr)
	append(& machine_code, ..mov_rax_instr)
	append(& machine_code, ..call_rax_instr)
	append(& machine_code, ..add_instr)
	append(& machine_code, ..ret_instr)
	
	fmt.printf("\nAssembled machine code: %d total bytes\n", len(machine_code))
	
	if len(machine_code) == 0 {
			fmt.println("Failed to generate machine code")
			return
	}
	
	fmt.printf("Generated %d bytes of machine code\n", len(machine_code))

	// Set up imports
	imports := []pe.Import_Info{
		{
				dll_name = "user32.dll",
				functions = make([dynamic]string),
		},
	}
	append(& imports[0].functions, "MessageBoxW")
	
	// Set up strings
	vars := []string {
		"Hello WINAPI!",
		"Smol Box: FROM SCRATCH"
	}
	
	// Generate the PE file
	pe_data := pe.encode(machine_code[:], vars, 0, imports )
	
	if len(pe_data) == 0 {
		fmt.println("Failed to generate PE file")
		return
	}
	
	// Write the PE file
	output_path := "generated_popup.exe"
	if err := os.write_entire_file(output_path, pe_data); err != nil {
		fmt.printf("Failed to write PE file: %v\n", err)
		return
	}
	
	fmt.printf("Generated PE file: %s (%d bytes)\n", output_path, len(pe_data))
	
	when (false) {

	// Try to execute the generated PE file
	fmt.println("Attempting to execute generated PE...")
	
	// Note: In a real scenario, you might want to validate the PE first
	// and ensure it's safe to execute
	
	desc := os.Process_Desc {
		command = {output_path},
	}

	success, stdout, stderr, exit_code := os.process_exec(desc, context.allocator)
	if success {
		fmt.printf("Generated PE executed successfully with exit code: %d\n", exit_code)
	} else {
		fmt.printf("Failed to execute generated PE, exit code: %d\n", exit_code)
	}

	}
}

main :: proc()
{
	varena : vmem.Arena; _ = vmem.arena_init_growing(& varena, mem.Megabyte * 128 ); context.allocator = vmem.arena_allocator(& varena)
	fmt.println("Hellope!")

	// winapi_popup_via_odin()
	winapi_popup_scratch()
}
