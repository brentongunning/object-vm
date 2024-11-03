// Push constants
pub const OP_0: u8 = 0;
pub const OP_PUSH: u8 = 0; // 0-75 (OP_PUSH0-OP_PUSH75)
pub const OP_PUSHDATA1: u8 = 76;
pub const OP_PUSHDATA2: u8 = 77;
pub const OP_PUSHDATA4: u8 = 78;
pub const OP_NEG1: u8 = 79;
pub const OP_1: u8 = 81;
pub const OP_2: u8 = 82;
pub const OP_3: u8 = 83;
pub const OP_4: u8 = 84;
pub const OP_5: u8 = 85;
pub const OP_6: u8 = 86;
pub const OP_7: u8 = 87;
pub const OP_8: u8 = 88;
pub const OP_9: u8 = 89;
pub const OP_10: u8 = 90;
pub const OP_11: u8 = 91;
pub const OP_12: u8 = 92;
pub const OP_13: u8 = 93;
pub const OP_14: u8 = 94;
pub const OP_15: u8 = 95;
pub const OP_16: u8 = 96;

// Flow control
pub const OP_VERIFY: u8 = 80;
pub const OP_IF: u8 = 97;
pub const OP_ELSE: u8 = 98;
pub const OP_ENDIF: u8 = 99;
pub const OP_NOT: u8 = 129;

// Stack
pub const OP_DUPN: u8 = 100;
pub const OP_DUP: u8 = 101;
pub const OP_DUP2: u8 = 102;
pub const OP_DUP3: u8 = 103;
pub const OP_DUP4: u8 = 104;
pub const OP_DUP5: u8 = 105;
pub const OP_DUP6: u8 = 106;
pub const OP_DUP7: u8 = 107;
pub const OP_DUP8: u8 = 108;
pub const OP_DUP9: u8 = 109;
pub const OP_SWAPN: u8 = 110;
pub const OP_SWAP: u8 = 111;
pub const OP_SWAP2: u8 = 112;
pub const OP_SWAP3: u8 = 113;
pub const OP_SWAP4: u8 = 114;
pub const OP_SWAP5: u8 = 115;
pub const OP_SWAP6: u8 = 116;
pub const OP_SWAP7: u8 = 117;
pub const OP_SWAP8: u8 = 118;
pub const OP_SWAP9: u8 = 119;
pub const OP_DROP: u8 = 120;
pub const OP_DEPTH: u8 = 121;
pub const OP_TOALTSTACK: u8 = 122;
pub const OP_FROMALTSTACK: u8 = 123;

// Data manipulation
pub const OP_CAT: u8 = 124;
pub const OP_SPLIT: u8 = 125;
pub const OP_SIZE: u8 = 126;
pub const OP_NUM2BIN: u8 = 127;
pub const OP_BIN2NUM: u8 = 128;

// Bitwise
pub const OP_INVERT: u8 = 130;
pub const OP_AND: u8 = 131;
pub const OP_OR: u8 = 132;
pub const OP_XOR: u8 = 133;
pub const OP_LSHIFT: u8 = 134;
pub const OP_RSHIFT: u8 = 135;
pub const OP_EQUAL: u8 = 136;

// Arithmetic
pub const OP_ADD: u8 = 137;
pub const OP_SUB: u8 = 138;
pub const OP_MUL: u8 = 139;
pub const OP_DIV: u8 = 140;
pub const OP_MOD: u8 = 141;
pub const OP_NUMEQUAL: u8 = 142;
pub const OP_LT: u8 = 143;
pub const OP_GT: u8 = 144;

// Cryptographic
pub const OP_BLAKE3: u8 = 145;
pub const OP_SHA256: u8 = 146;

// Authorization
pub const OP_SIGN: u8 = 147;
pub const OP_SIGNTO: u8 = 148;

// Transaction
pub const OP_UNIQUIFIER: u8 = 149; // Ensures txid is unique. Next 36 bytes is a location.

// Objects
pub const OP_DEPLOY: u8 = 150;
pub const OP_CREATE: u8 = 151;
pub const OP_CALL: u8 = 152;
pub const OP_STATE: u8 = 153;
pub const OP_CONTRACT: u8 = 154;

// Funding
pub const OP_FUND: u8 = 155;
