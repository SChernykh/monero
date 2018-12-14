#ifndef VARIANT4_RANDOM_MATH_H
#define VARIANT4_RANDOM_MATH_H

// Register size can be configured to either 32 bit (uint32_t) or 64 bit (uint64_t)
typedef uint32_t v4_reg;

enum V4_Settings
{
	// Generate code with latency = 54 cycles, which is equivalent to 18 multiplications
	TOTAL_LATENCY = 18 * 3,
	
	// Available ALUs for MUL
	// Modern CPUs typically have only 1 ALU which can do multiplications
	ALU_COUNT_MUL = 1,

	// Total available ALUs
	// Modern CPUs have 3-4 ALUs, but we use only 2 because random math executes together with other main loop code
	ALU_COUNT = 2,
};

enum V4_InstructionList
{
	MUL,	// a*b
	ADD,	// a+b + C, -128 <= C <= 127
	SUB,	// a-b
	ROR,	// rotate right "a" by "b & 31" bits
	ROL,	// rotate left "a" by "b & 31" bits
	XOR,	// a^b
	RET,	// finish execution
	V4_INSTRUCTION_COUNT = RET,
};

// V4_InstructionCompact is used to generate code from random data
// Every random sequence of bytes is a valid code
//
// Instruction encoding is 1 byte for all instructions except ADD
// ADD instruction uses second byte for constant "C" in "a+b+C"
//
// There are 8 registers in total:
// - 4 variable registers
// - 4 constant registers initialized from loop variables
//
// This is why dst_index is 2 bits
struct V4_InstructionCompact
{
	uint8_t opcode : 3;
	uint8_t dst_index : 2;
	uint8_t src_index : 3;
};

struct V4_Instruction
{
	uint8_t opcode;
	uint8_t dst_index;
	uint8_t src_index;
	int8_t C;
};

#ifndef FORCEINLINE
#ifdef __GNUC__
#define FORCEINLINE __attribute__((always_inline)) inline
#else
#define FORCEINLINE __forceinline
#endif
#endif

#ifndef UNREACHABLE_CODE
#ifdef __GNUC__
#define UNREACHABLE_CODE __builtin_unreachable()
#else
#define UNREACHABLE_CODE __assume(false)
#endif
#endif

// Random math interpreter's loop is fully unrolled and inlined to achieve 100% branch prediction on CPU:
// every switch-case will point to the same destination on every iteration of Cryptonight main loop
//
// This is about as fast as it can get without using low-level machine code generation
static FORCEINLINE void v4_random_math(const struct V4_Instruction* code, v4_reg* r)
{
	enum
	{
		REG_BITS = sizeof(v4_reg) * 8,
	};

#define V4_EXEC(i) \
	{ \
		const struct V4_Instruction* op = code + i; \
		const v4_reg src = r[op->src_index]; \
		v4_reg* dst = r + op->dst_index; \
		switch (op->opcode) \
		{ \
		case MUL: \
			*dst *= src; \
			break; \
		case ADD: \
			*dst += src + op->C; \
			break; \
		case SUB: \
			*dst -= src; \
			break; \
		case ROR: \
			{ \
				const uint32_t shift = src % REG_BITS; \
				*dst = (*dst >> shift) | (*dst << (REG_BITS - shift)); \
			} \
			break; \
		case ROL: \
			{ \
				const uint32_t shift = src % REG_BITS; \
				*dst = (*dst << shift) | (*dst >> (REG_BITS - shift)); \
			} \
			break; \
		case XOR: \
			*dst ^= src; \
			break; \
		case RET: \
			return; \
		default: \
			UNREACHABLE_CODE; \
			break; \
		} \
	}

#define V4_EXEC_10(j) \
	V4_EXEC(j + 0) \
	V4_EXEC(j + 1) \
	V4_EXEC(j + 2) \
	V4_EXEC(j + 3) \
	V4_EXEC(j + 4) \
	V4_EXEC(j + 5) \
	V4_EXEC(j + 6) \
	V4_EXEC(j + 7) \
	V4_EXEC(j + 8) \
	V4_EXEC(j + 9)

	// Generated program can have up to 109 instructions (54*2+1: 54 clock cycles with 2 ALUs running + one final RET instruction)
	V4_EXEC_10(0);		// instructions 0-9
	V4_EXEC_10(10);		// instructions 10-19
	V4_EXEC_10(20);		// instructions 20-29
	V4_EXEC_10(30);		// instructions 30-39
	V4_EXEC_10(40);		// instructions 40-49
	V4_EXEC_10(50);		// instructions 50-59
	V4_EXEC_10(60);		// instructions 60-69
	V4_EXEC_10(70);		// instructions 70-79
	V4_EXEC_10(80);		// instructions 80-89
	V4_EXEC_10(90);		// instructions 90-99
	V4_EXEC_10(100);	// instructions 100-109

#undef V4_EXEC_10
#undef V4_EXEC
}

// Generates as many random math operations as possible with given latency and ALU restrictions
static inline void v4_random_math_init(struct V4_Instruction* code, const uint64_t height)
{
	// MUL is 3 cycles, all other operations are 1 cycle
	const int op_latency[V4_INSTRUCTION_COUNT] = { 3, 1, 1, 1, 1, 1 };

	// Available ALUs for each instruction
	const int op_ALUs[V4_INSTRUCTION_COUNT] = { ALU_COUNT_MUL, ALU_COUNT, ALU_COUNT, ALU_COUNT, ALU_COUNT, ALU_COUNT };

	char data[32];
	memset(data, 0, sizeof(data));
	*((uint64_t*)data) = height;

	size_t data_index = sizeof(data);

	int latency[8];
	bool alu_busy[TOTAL_LATENCY][ALU_COUNT];

	memset(latency, 0, sizeof(latency));
	memset(alu_busy, 0, sizeof(alu_busy));

	int num_retries = 0;
	int code_size = 0;

	while (((latency[0] < TOTAL_LATENCY) || (latency[1] < TOTAL_LATENCY) || (latency[2] < TOTAL_LATENCY) || (latency[3] < TOTAL_LATENCY)) && (num_retries < 64))
	{
		// If we don't have data available, generate more
		if (data_index >= sizeof(data))
		{
			hash_extra_blake(data, sizeof(data), data);
			data_index = 0;
		}
		struct V4_InstructionCompact op = ((struct V4_InstructionCompact*)data)[data_index++];

		// MUL uses opcodes 0-2 (it's 3 times more frequent than other instructions)
		// ADD, SUB, ROR, ROL, XOR use opcodes 3-7
		const uint8_t opcode = (op.opcode > 2) ? (op.opcode - 2) : 0;
		const int a = op.dst_index;
		int b = op.src_index;

		// Make sure we don't do SUB/XOR with the same register
		if (((opcode == SUB) || (opcode == XOR)) && (a == b))
		{
			// a is always < 4, so we don't need to check bounds here
			b = a + 4;
			op.src_index = b;
		}

		// Find which ALU is available (and when) for this instruction
		int next_latency = (latency[a] > latency[b]) ? latency[a] : latency[b];
		int alu_index = -1;
		while ((next_latency < TOTAL_LATENCY) && (alu_index < 0))
		{
			for (int i = op_ALUs[opcode] - 1; i >= 0; --i)
			{
				if (!alu_busy[next_latency][i])
				{
					alu_index = i;
					break;
				}
			}
			++next_latency;
		}
		next_latency += op_latency[opcode];

		if (next_latency <= TOTAL_LATENCY)
		{
			alu_busy[next_latency - op_latency[opcode]][alu_index] = true;
			latency[a] = next_latency;
			code[code_size].opcode = opcode;
			code[code_size].dst_index = op.dst_index;
			code[code_size].src_index = op.src_index;
			code[code_size].C = 0;

			// ADD instruction is 2 bytes long. Second byte is a signed constant "C" in "a = a + b + C"
			if (opcode == ADD)
			{
				// If we don't have data available, generate more
				if (data_index >= sizeof(data))
				{
					hash_extra_blake(data, sizeof(data), data);
					data_index = 0;
				}
				code[code_size].C = (int8_t) data[data_index++];
			}
			++code_size;
		}
		else
		{
			++num_retries;
		}
	}

	// Add final instruction to stop the interpreter
	code[code_size].opcode = RET;
	code[code_size].dst_index = 0;
	code[code_size].src_index = 0;
	code[code_size].C = 0;
}

#endif
