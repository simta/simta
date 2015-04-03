/*
 * Copyright (c) Regents of The University of Michigan
 * See COPYING.
 */

#include "config.h"
#include "base64.h"

/*
 * These tables are generated by base64gen.
 */
static char	etab_high6[ 256 ] = {
 'A', 'A', 'A', 'A', 'B', 'B', 'B', 'B',
 'C', 'C', 'C', 'C', 'D', 'D', 'D', 'D',
 'E', 'E', 'E', 'E', 'F', 'F', 'F', 'F',
 'G', 'G', 'G', 'G', 'H', 'H', 'H', 'H',
 'I', 'I', 'I', 'I', 'J', 'J', 'J', 'J',
 'K', 'K', 'K', 'K', 'L', 'L', 'L', 'L',
 'M', 'M', 'M', 'M', 'N', 'N', 'N', 'N',
 'O', 'O', 'O', 'O', 'P', 'P', 'P', 'P',
 'Q', 'Q', 'Q', 'Q', 'R', 'R', 'R', 'R',
 'S', 'S', 'S', 'S', 'T', 'T', 'T', 'T',
 'U', 'U', 'U', 'U', 'V', 'V', 'V', 'V',
 'W', 'W', 'W', 'W', 'X', 'X', 'X', 'X',
 'Y', 'Y', 'Y', 'Y', 'Z', 'Z', 'Z', 'Z',
 'a', 'a', 'a', 'a', 'b', 'b', 'b', 'b',
 'c', 'c', 'c', 'c', 'd', 'd', 'd', 'd',
 'e', 'e', 'e', 'e', 'f', 'f', 'f', 'f',
 'g', 'g', 'g', 'g', 'h', 'h', 'h', 'h',
 'i', 'i', 'i', 'i', 'j', 'j', 'j', 'j',
 'k', 'k', 'k', 'k', 'l', 'l', 'l', 'l',
 'm', 'm', 'm', 'm', 'n', 'n', 'n', 'n',
 'o', 'o', 'o', 'o', 'p', 'p', 'p', 'p',
 'q', 'q', 'q', 'q', 'r', 'r', 'r', 'r',
 's', 's', 's', 's', 't', 't', 't', 't',
 'u', 'u', 'u', 'u', 'v', 'v', 'v', 'v',
 'w', 'w', 'w', 'w', 'x', 'x', 'x', 'x',
 'y', 'y', 'y', 'y', 'z', 'z', 'z', 'z',
 '0', '0', '0', '0', '1', '1', '1', '1',
 '2', '2', '2', '2', '3', '3', '3', '3',
 '4', '4', '4', '4', '5', '5', '5', '5',
 '6', '6', '6', '6', '7', '7', '7', '7',
 '8', '8', '8', '8', '9', '9', '9', '9',
 '+', '+', '+', '+', '/', '/', '/', '/',
};

static char	etab_high24[ 256 ] = {
 'A', 'Q', 'g', 'w', 'A', 'Q', 'g', 'w',
 'A', 'Q', 'g', 'w', 'A', 'Q', 'g', 'w',
 'B', 'R', 'h', 'x', 'B', 'R', 'h', 'x',
 'B', 'R', 'h', 'x', 'B', 'R', 'h', 'x',
 'C', 'S', 'i', 'y', 'C', 'S', 'i', 'y',
 'C', 'S', 'i', 'y', 'C', 'S', 'i', 'y',
 'D', 'T', 'j', 'z', 'D', 'T', 'j', 'z',
 'D', 'T', 'j', 'z', 'D', 'T', 'j', 'z',
 'E', 'U', 'k', '0', 'E', 'U', 'k', '0',
 'E', 'U', 'k', '0', 'E', 'U', 'k', '0',
 'F', 'V', 'l', '1', 'F', 'V', 'l', '1',
 'F', 'V', 'l', '1', 'F', 'V', 'l', '1',
 'G', 'W', 'm', '2', 'G', 'W', 'm', '2',
 'G', 'W', 'm', '2', 'G', 'W', 'm', '2',
 'H', 'X', 'n', '3', 'H', 'X', 'n', '3',
 'H', 'X', 'n', '3', 'H', 'X', 'n', '3',
 'I', 'Y', 'o', '4', 'I', 'Y', 'o', '4',
 'I', 'Y', 'o', '4', 'I', 'Y', 'o', '4',
 'J', 'Z', 'p', '5', 'J', 'Z', 'p', '5',
 'J', 'Z', 'p', '5', 'J', 'Z', 'p', '5',
 'K', 'a', 'q', '6', 'K', 'a', 'q', '6',
 'K', 'a', 'q', '6', 'K', 'a', 'q', '6',
 'L', 'b', 'r', '7', 'L', 'b', 'r', '7',
 'L', 'b', 'r', '7', 'L', 'b', 'r', '7',
 'M', 'c', 's', '8', 'M', 'c', 's', '8',
 'M', 'c', 's', '8', 'M', 'c', 's', '8',
 'N', 'd', 't', '9', 'N', 'd', 't', '9',
 'N', 'd', 't', '9', 'N', 'd', 't', '9',
 'O', 'e', 'u', '+', 'O', 'e', 'u', '+',
 'O', 'e', 'u', '+', 'O', 'e', 'u', '+',
 'P', 'f', 'v', '/', 'P', 'f', 'v', '/',
 'P', 'f', 'v', '/', 'P', 'f', 'v', '/',
};

static char	etab_low42[ 256 ] = {
 'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
 'g', 'k', 'o', 's', 'w', '0', '4', '8',
 'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
 'g', 'k', 'o', 's', 'w', '0', '4', '8',
 'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
 'g', 'k', 'o', 's', 'w', '0', '4', '8',
 'A', 'E', 'I', 'M', 'Q', 'U', 'Y', 'c',
 'g', 'k', 'o', 's', 'w', '0', '4', '8',
 'B', 'F', 'J', 'N', 'R', 'V', 'Z', 'd',
 'h', 'l', 'p', 't', 'x', '1', '5', '9',
 'B', 'F', 'J', 'N', 'R', 'V', 'Z', 'd',
 'h', 'l', 'p', 't', 'x', '1', '5', '9',
 'B', 'F', 'J', 'N', 'R', 'V', 'Z', 'd',
 'h', 'l', 'p', 't', 'x', '1', '5', '9',
 'B', 'F', 'J', 'N', 'R', 'V', 'Z', 'd',
 'h', 'l', 'p', 't', 'x', '1', '5', '9',
 'C', 'G', 'K', 'O', 'S', 'W', 'a', 'e',
 'i', 'm', 'q', 'u', 'y', '2', '6', '+',
 'C', 'G', 'K', 'O', 'S', 'W', 'a', 'e',
 'i', 'm', 'q', 'u', 'y', '2', '6', '+',
 'C', 'G', 'K', 'O', 'S', 'W', 'a', 'e',
 'i', 'm', 'q', 'u', 'y', '2', '6', '+',
 'C', 'G', 'K', 'O', 'S', 'W', 'a', 'e',
 'i', 'm', 'q', 'u', 'y', '2', '6', '+',
 'D', 'H', 'L', 'P', 'T', 'X', 'b', 'f',
 'j', 'n', 'r', 'v', 'z', '3', '7', '/',
 'D', 'H', 'L', 'P', 'T', 'X', 'b', 'f',
 'j', 'n', 'r', 'v', 'z', '3', '7', '/',
 'D', 'H', 'L', 'P', 'T', 'X', 'b', 'f',
 'j', 'n', 'r', 'v', 'z', '3', '7', '/',
 'D', 'H', 'L', 'P', 'T', 'X', 'b', 'f',
 'j', 'n', 'r', 'v', 'z', '3', '7', '/',
};

static char	etab_low6[ 256 ] = {
 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
 'w', 'x', 'y', 'z', '0', '1', '2', '3',
 '4', '5', '6', '7', '8', '9', '+', '/',
 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
 'w', 'x', 'y', 'z', '0', '1', '2', '3',
 '4', '5', '6', '7', '8', '9', '+', '/',
 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
 'w', 'x', 'y', 'z', '0', '1', '2', '3',
 '4', '5', '6', '7', '8', '9', '+', '/',
 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
 'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
 'w', 'x', 'y', 'z', '0', '1', '2', '3',
 '4', '5', '6', '7', '8', '9', '+', '/',
};

static unsigned char	dtab_high6[ 256 ] = {
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0xf8, 0x00, 0x00, 0x00, 0xfc,
 0xd0, 0xd4, 0xd8, 0xdc, 0xe0, 0xe4, 0xe8, 0xec,
 0xf0, 0xf4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x04, 0x08, 0x0c, 0x10, 0x14, 0x18,
 0x1c, 0x20, 0x24, 0x28, 0x2c, 0x30, 0x34, 0x38,
 0x3c, 0x40, 0x44, 0x48, 0x4c, 0x50, 0x54, 0x58,
 0x5c, 0x60, 0x64, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x68, 0x6c, 0x70, 0x74, 0x78, 0x7c, 0x80,
 0x84, 0x88, 0x8c, 0x90, 0x94, 0x98, 0x9c, 0xa0,
 0xa4, 0xa8, 0xac, 0xb0, 0xb4, 0xb8, 0xbc, 0xc0,
 0xc4, 0xc8, 0xcc, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static unsigned char	dtab_high2[ 256 ] = {
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x03,
 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03, 0x03,
 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01,
 0x01, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x02,
 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x03,
 0x03, 0x03, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static unsigned char	dtab_high4[ 256 ] = {
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0xe0, 0x00, 0x00, 0x00, 0xf0,
 0x40, 0x50, 0x60, 0x70, 0x80, 0x90, 0xa0, 0xb0,
 0xc0, 0xd0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
 0x70, 0x80, 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0,
 0xf0, 0x00, 0x10, 0x20, 0x30, 0x40, 0x50, 0x60,
 0x70, 0x80, 0x90, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
 0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
 0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
 0x10, 0x20, 0x30, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static unsigned char	dtab_low4[ 256 ] = {
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x0f, 0x00, 0x00, 0x00, 0x0f,
 0x0d, 0x0d, 0x0d, 0x0d, 0x0e, 0x0e, 0x0e, 0x0e,
 0x0f, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01,
 0x01, 0x02, 0x02, 0x02, 0x02, 0x03, 0x03, 0x03,
 0x03, 0x04, 0x04, 0x04, 0x04, 0x05, 0x05, 0x05,
 0x05, 0x06, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x06, 0x06, 0x07, 0x07, 0x07, 0x07, 0x08,
 0x08, 0x08, 0x08, 0x09, 0x09, 0x09, 0x09, 0x0a,
 0x0a, 0x0a, 0x0a, 0x0b, 0x0b, 0x0b, 0x0b, 0x0c,
 0x0c, 0x0c, 0x0c, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static unsigned char	dtab_low2[ 256 ] = {
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x80, 0x00, 0x00, 0x00, 0xc0,
 0x00, 0x40, 0x80, 0xc0, 0x00, 0x40, 0x80, 0xc0,
 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x40, 0x80, 0xc0, 0x00, 0x40, 0x80,
 0xc0, 0x00, 0x40, 0x80, 0xc0, 0x00, 0x40, 0x80,
 0xc0, 0x00, 0x40, 0x80, 0xc0, 0x00, 0x40, 0x80,
 0xc0, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x80, 0xc0, 0x00, 0x40, 0x80, 0xc0, 0x00,
 0x40, 0x80, 0xc0, 0x00, 0x40, 0x80, 0xc0, 0x00,
 0x40, 0x80, 0xc0, 0x00, 0x40, 0x80, 0xc0, 0x00,
 0x40, 0x80, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

static unsigned char	dtab_low6[ 256 ] = {
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x3e, 0x00, 0x00, 0x00, 0x3f,
 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b,
 0x3c, 0x3d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
 0x17, 0x18, 0x19, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30,
 0x31, 0x32, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
};

/*
 * Caller is assumed to have allocated enough space in e, given the size
 * of d, plus null termination.  See SZ_BASE64_E() macro.
 */
    void
base64_e( unsigned char *d, int dlen, char *e )
{
    int			i;

    i = dlen / 3;

    while ( i > 0 ) {
	e[ 0 ] = etab_high6[ d[ 0 ]];
	e[ 1 ] = etab_high24[ ( d[ 0 ] & 0x03 ) | ( d[ 1 ] & 0xF0 ) ];
	e[ 2 ] = etab_low42[ ( d[ 1 ] & 0x0F ) | ( d[ 2 ] & 0xC0 ) ];
	e[ 3 ] = etab_low6[ d[ 2 ]];

	d += 3;
	e += 4;
	i--;
    }

    switch ( dlen % 3 ) {
    case 2 :
	e[ 0 ] = etab_high6[ d[ 0 ]];
	e[ 1 ] = etab_high24[ ( d[ 0 ] & 0x03 ) | ( d[ 1 ] & 0xF0 ) ];
	e[ 2 ] = etab_low42[ d[ 1 ] & 0x0F ];
	e[ 3 ] = '=';
	e[ 4 ] = '\0';
	return;

    case 1 :
	e[ 0 ] = etab_high6[ d[ 0 ]];
	e[ 1 ] = etab_high24[ d[ 0 ] & 0x03 ];
	e[ 2 ] = '=';
	e[ 3 ] = '=';
	e[ 4 ] = '\0';
	return;
    
    default:
	e[ 0 ] = '\0';
	return;
    }
}

/*
 * elen must be a multiple of 4, d is assumed to be at least 3/4 of elen.
 * See SZ_BASE64_D() macro.
 */
    void
base64_d( char *e, int elen, unsigned char *d )
{
    int			i;

    i = elen / 4;

    while ( i > 0 ) {
	d[ 0 ] = dtab_high6[ (int)e[ 0 ]] | dtab_high2[ (int)e[ 1 ]];
	d[ 1 ] = dtab_high4[ (int)e[ 1 ]] | dtab_low4[ (int)e[ 2 ]];
	d[ 2 ] = dtab_low2[ (int)e[ 2 ]] | dtab_low6[ (int)e[ 3 ]];

	d += 3;
	e += 4;
	i--;
    }
    return;
}
/* vim: set softtabstop=4 shiftwidth=4 noexpandtab :*/
