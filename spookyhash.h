#ifndef __SPOOKYHASH
#define __SPOOKYHASH

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define sc_num_vars (12)
#define sc_block_size (8 * sc_num_vars)
#define sc_buf_size (2 * sc_block_size)

#define sc_const 0xdeadbeefdeadbeefLL

#define ALLOW_UNALIGNED_READS 1

////////////////////////////////////////////////////////////////////////////////
//	STATEFUL HASHING
//
//	this allows for the digestion of a message in multiple parts
//	hashing this way results in the same hash as the concatenated parts
////////////////////////////////////////////////////////////////////////////////
typedef
struct
{
	uint64_t	 data[2*sc_num_vars];
	uint64_t	 state[sc_num_vars];
	size_t		 length;
	uint8_t		 remainder;
} spookyhash_state_t;

////////////////////////////////////////
//	copy state to another variable
////////////////////////////////////////
void
spookyhash_clone_state
(
	spookyhash_state_t	*old_state,
	spookyhash_state_t	*new_state
);

////////////////////////////////////////
//	initialize the state
////////////////////////////////////////
void
spookyhash_init
(
	spookyhash_state_t	*state,
	uint64_t		 seed1,
	uint64_t		 seed2
);

////////////////////////////////////////
//	digest message
//		(in parts or whole)
////////////////////////////////////////
void
spookyhash_update
(
	spookyhash_state_t	*state,
	const void		*message,
	size_t			 length
);

////////////////////////////////////////
//	finalize the hash
//
//	does not modify state
////////////////////////////////////////
void
spookyhash_final
(
	spookyhash_state_t	*state,
	uint64_t		*hash1,
	uint64_t		*hash2
);

////////////////////////////////////////////////////////////////////////////////
//	STATELESS HASHING
////////////////////////////////////////////////////////////////////////////////
void
spookyhash128
(
	const void		*message,
	size_t			 length,
	uint64_t		*hash1,
	uint64_t		*hash2
);

uint64_t
spookyhash64
(
	const void		*message,
	size_t			 length,
	uint64_t		 seed
);

uint32_t
spookyhash32
(
	const void		*message,
	size_t			 length,
	uint32_t		 seed
);

#endif /* __SPOOKYHASH */
