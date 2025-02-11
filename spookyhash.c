#include "spookyhash.h"

#define rotate(x,k) (((x) << (k)) | ((x) >> (64 - (k))))

void
spookyhash_clone_state
(
	spookyhash_state_t	*old_state,
	spookyhash_state_t	*new_state
)
{
	memcpy(new_state,old_state,sizeof(spookyhash_state_t));
}

static
inline
void
short_mix
(
	uint64_t	*s0,
	uint64_t	*s1,
	uint64_t	*s2,
	uint64_t	*s3
)
{
	*s2 = rotate(*s2,50);
	*s2 += *s3;
	*s0 ^= *s2;

	*s3 = rotate(*s3,52);
	*s3 += *s0;
	*s1 ^= *s3;

	*s0 = rotate(*s0,30);
	*s0 += *s1;
	*s2 ^= *s0;

	*s1 = rotate(*s1,41);
	*s1 += *s2;
	*s3 ^= *s1;

	*s2 = rotate(*s2,54);
	*s2 += *s3;
	*s0 ^= *s2;

	*s3 = rotate(*s3,48);
	*s3 += *s0;
	*s1 ^= *s3;

	*s0 = rotate(*s0,38);
	*s0 += *s1;
	*s2 ^= *s0;

	*s1 = rotate(*s1,37);
	*s1 += *s2;
	*s3 ^= *s1;

	*s2 = rotate(*s2,62);
	*s2 += *s3;
	*s0 ^= *s2;

	*s3 = rotate(*s3,34);
	*s3 += *s0;
	*s1 ^= *s3;

	*s0 = rotate(*s0,5);
	*s0 += *s1;
	*s2 ^= *s0;

	*s1 = rotate(*s1,36);
	*s1 += *s2;
	*s3 ^= *s1;
}

static
inline
void
short_end
(
	uint64_t	*s0,
	uint64_t	*s1,
	uint64_t	*s2,
	uint64_t	*s3
)
{
	*s3 ^= *s2;
	*s2 = rotate(*s2,15);
	*s3 += *s2;

	*s0 ^= *s3;
	*s3 = rotate(*s3,52);
	*s0 += *s3;

	*s1 ^= *s0;
	*s0 = rotate(*s0,26);
	*s1 += *s0;

	*s2 ^= *s1;
	*s1 = rotate(*s1,51);
	*s2 += *s1;

	*s3 ^= *s2;
	*s2 = rotate(*s2,28);
	*s3 += *s2;

	*s0 ^= *s3;
	*s3 = rotate(*s3,9);
	*s0 += *s3;

	*s1 ^= *s0;
	*s0 = rotate(*s0,47);
	*s1 += *s0;

	*s2 ^= *s1;
	*s1 = rotate(*s1,54);
	*s2 += *s1;

	*s3 ^= *s2;
	*s2 = rotate(*s2,32);
	*s3 += *s2;

	*s0 ^= *s3;
	*s3 = rotate(*s3,25);
	*s0 += *s3;

	*s1 ^= *s0;
	*s0 = rotate(*s0,63);
	*s1 += *s0;
}

static
inline
void
spookyhash_short
(
	const void		*message,
	size_t			 length,
	uint64_t		*hash1,
	uint64_t		*hash2,
	spookyhash_state_t	*state
)
{
	spookyhash_state_t s = {0};

	if(state == 0)
	{
		state = &s;
	}

	uint64_t buf[2*sc_num_vars];
	union
	{
		const uint8_t	*p8;
		uint32_t	*p32;
		uint64_t	*p64;
		size_t		 i;
	} u;

	u.p8 = message;

	if(!ALLOW_UNALIGNED_READS && (u.i & 0x7))
	{
		memcpy(buf,message,length);
		u.p64 = buf;
	}

	size_t remainder = length % 32;
	uint64_t a = *hash1;
	uint64_t b = *hash2;
	uint64_t c = sc_const;
	uint64_t d = sc_const;

	if(length > 15)
	{
		const uint64_t *end_p = u.p64 + (length / 32) * 4;
		while(u.p64 < end_p)
		{
			c += u.p64[0];
			d += u.p64[1];

			short_mix(&a,&b,&c,&d);

			a += u.p64[2];
			b += u.p64[3];

			u.p64 += 4;
		}

		if(remainder >= 16)
		{
			c += u.p64[0];
			d += u.p64[1];

			short_mix(&a,&b,&c,&d);

			u.p64 += 2;
			remainder -= 16;
		}
	}

	d += ((uint64_t) length << 56);

	switch(remainder)
	{
		case 15:
			d += ((uint64_t) u.p8[14]) << 56;
		case 14:
			d += ((uint64_t) u.p8[13]) << 40;
		case 13:
			d += ((uint64_t) u.p8[12]) << 32;
		case 12:
			d += u.p32[2];
			c += u.p64[0];
			break;
		case 11:
			d += ((uint64_t) u.p8[10]) << 16;
		case 10:
			d += ((uint64_t) u.p8[9]) << 8;
		case 9:
			d += (uint64_t) u.p8[8];
		case 8:
			c += u.p64[0];
			break;
		case 7:
			c += ((uint64_t) u.p8[6]) << 48;
		case 6:
			c += ((uint64_t) u.p8[5]) << 40;
		case 5:
			c += ((uint64_t) u.p8[4]) << 32;
		case 4:
			c += u.p32[0];
			break;
		case 3:
			c += ((uint64_t) u.p8[2]) << 16;
		case 2:
			c += ((uint64_t) u.p8[1]) << 8;
		case 1:
			c += (uint64_t) u.p8[0];
			break;
		case 0:
			c += sc_const;
			d += sc_const;
	}

	short_end(&a,&b,&c,&d);

	*hash1 = a;
	*hash2 = b;
}

static
inline
void
mix
(
	const uint64_t	*data,
	uint64_t	*s0,
	uint64_t	*s1,
	uint64_t	*s2,
	uint64_t	*s3,
	uint64_t	*s4,
	uint64_t	*s5,
	uint64_t	*s6,
	uint64_t	*s7,
	uint64_t	*s8,
	uint64_t	*s9,
	uint64_t	*s10,
	uint64_t	*s11
)
{
	*s0 += data[0];
	*s2 ^= *s10;
	*s11 ^= *s0;
	*s0 = rotate(*s0,11);
	*s11 += *s1;

	*s1 += data[1];
	*s3 ^= *s11;
	*s0 ^= *s1;
	*s1 = rotate(*s1,32);
	*s0 += *s2;

	*s2 += data[2];
	*s4 ^= *s0;
	*s1 ^= *s2;
	*s2 = rotate(*s2,43);
	*s1 += *s3;

	*s3 += data[3];
	*s5 ^= *s1;
	*s2 ^= *s3;
	*s3 = rotate(*s3,31);
	*s2 += *s4;

	*s4 += data[4];
	*s6 ^= *s2;
	*s3 ^= *s4;
	*s4 = rotate(*s4,17);
	*s3 += *s5;

	*s5 += data[5];
	*s7 ^= *s3;
	*s4 ^= *s5;
	*s5 = rotate(*s5,28);
	*s4 += *s6;

	*s6 += data[6];
	*s8 ^= *s4;
	*s5 ^= *s6;
	*s6 = rotate(*s6,39);
	*s5 += *s7;

	*s7 += data[7];
	*s9 ^= *s5;
	*s6 ^= *s7;
	*s7 = rotate(*s7,57);
	*s6 += *s8;

	*s8 += data[8];
	*s10 ^= *s6;
	*s7 ^= *s8;
	*s8 = rotate(*s8,55);
	*s7 += *s9;

	*s9 += data[9];
	*s11 ^= *s7;
	*s8 ^= *s9;
	*s9 = rotate(*s9,54);
	*s8 += *s10;

	*s10 += data[10];
	*s0 ^= *s8;
	*s9 ^= *s10;
	*s10 = rotate(*s10,22);
	*s9 += *s11;

	*s11 += data[11];
	*s1 ^= *s9;
	*s10 ^= *s11;
	*s11 = rotate(*s11,46);
	*s10 += *s0;
}

static
inline
void
end_partial
(
	uint64_t	*s0,
	uint64_t	*s1,
	uint64_t	*s2,
	uint64_t	*s3,
	uint64_t	*s4,
	uint64_t	*s5,
	uint64_t	*s6,
	uint64_t	*s7,
	uint64_t	*s8,
	uint64_t	*s9,
	uint64_t	*s10,
	uint64_t	*s11
)
{
	*s11 += *s1;
	*s2 ^= *s11;
	*s1 = rotate(*s1,44);

	*s0 += *s2;
	*s3 ^= *s0;
	*s2 = rotate(*s2,15);

	*s1 += *s3;
	*s4 ^= *s1;
	*s3 = rotate(*s3,34);

	*s2 += *s4;
	*s5 ^= *s2;
	*s4 = rotate(*s4,21);

	*s3 += *s5;
	*s6 ^= *s3;
	*s5 = rotate(*s5,38);

	*s4 += *s6;
	*s7 ^= *s4;
	*s6 = rotate(*s6,33);

	*s5 += *s7;
	*s8 ^= *s5;
	*s7 = rotate(*s7,10);

	*s6 += *s8;
	*s9 ^= *s6;
	*s8 = rotate(*s8,13);

	*s7 += *s9;
	*s10 ^= *s7;
	*s9 = rotate(*s9,38);

	*s8 += *s10;
	*s11 ^= *s8;
	*s10 = rotate(*s10,53);

	*s9 += *s11;
	*s0 ^= *s9;
	*s11 = rotate(*s11,42);

	*s10 += *s0;
	*s1 ^= *s10;
	*s0 = rotate(*s0,54);
}

static
inline
void
end
(
	const uint64_t	*data,
	uint64_t	*s0,
	uint64_t	*s1,
	uint64_t	*s2,
	uint64_t	*s3,
	uint64_t	*s4,
	uint64_t	*s5,
	uint64_t	*s6,
	uint64_t	*s7,
	uint64_t	*s8,
	uint64_t	*s9,
	uint64_t	*s10,
	uint64_t	*s11
)
{
	*s0 = data[0];
	*s1 = data[1];
	*s2 = data[2];
	*s3 = data[3];
	*s4 = data[4];
	*s5 = data[5];
	*s6 = data[6];
	*s7 = data[7];
	*s8 = data[8];
	*s9 = data[9];
	*s10 = data[10];
	*s11 = data[11];

	end_partial(
		s0,
		s1,
		s2,
		s3,
		s4,
		s5,
		s6,
		s7,
		s8,
		s9,
		s10,
		s11
	);
	end_partial(
		s0,
		s1,
		s2,
		s3,
		s4,
		s5,
		s6,
		s7,
		s8,
		s9,
		s10,
		s11
	);
	end_partial(
		s0,
		s1,
		s2,
		s3,
		s4,
		s5,
		s6,
		s7,
		s8,
		s9,
		s10,
		s11
	);
}

void
spookyhash_init
(
	spookyhash_state_t	*state,
	uint64_t		 seed1,
	uint64_t		 seed2
)
{
	state->length = 0;
	state->remainder = 0;
	state->state[0] = seed1;
	state->state[1] = seed2;
}

void
spookyhash_update
(
	spookyhash_state_t	*state,
	const void		*message,
	size_t			 length
)
{
	uint64_t s0;
	uint64_t s1;
	uint64_t s2;
	uint64_t s3;
	uint64_t s4;
	uint64_t s5;
	uint64_t s6;
	uint64_t s7;
	uint64_t s8;
	uint64_t s9;
	uint64_t s10;
	uint64_t s11;

	size_t new_length = length + state->remainder;
	uint8_t remainder;
	union
	{
		const uint8_t	*p8;
		uint64_t	*p64;
		size_t		 i;
	} u;
	const uint64_t *end_p;

	if(new_length < sc_buf_size)
	{
		memcpy(&((uint8_t *) state->data)[state->remainder],message,length);
		state->length = length + state->length;
		state->remainder = (uint8_t) new_length;
		return;
	}

	if(state->length < sc_buf_size)
	{
		s0 = state->state[0];
		s3 = state->state[0];
		s6 = state->state[0];
		s9 = state->state[0];

		s1 = state->state[1];
		s4 = state->state[1];
		s7 = state->state[1];
		s10 = state->state[1];

		s2 = sc_const;
		s5 = sc_const;
		s8 = sc_const;
		s11 = sc_const;
	}
	else
	{
		s0 = state->state[0];
		s1 = state->state[1];
		s2 = state->state[2];
		s3 = state->state[3];
		s4 = state->state[4];
		s5 = state->state[5];
		s6 = state->state[6];
		s7 = state->state[7];
		s8 = state->state[8];
		s9 = state->state[9];
		s10 = state->state[10];
		s11 = state->state[11];
	}
	state->length = length + state->length;

	if(state->remainder)
	{
		uint8_t prefix = sc_buf_size - state->remainder;
		memcpy(&((uint8_t *) state->data)[state->remainder],message,prefix);
		u.p64 = state->data;
		mix(
			u.p64,
			&s0,
			&s1,
			&s2,
			&s3,
			&s4,
			&s5,
			&s6,
			&s7,
			&s8,
			&s9,
			&s10,
			&s11
		);
		mix(
			&u.p64[sc_num_vars],
			&s0,
			&s1,
			&s2,
			&s3,
			&s4,
			&s5,
			&s6,
			&s7,
			&s8,
			&s9,
			&s10,
			&s11
		);
		u.p8 = ((const uint8_t *) message) + prefix;
		length -= prefix;
	}
	else
	{
		u.p8 = (const uint8_t *) message;
	}

	end_p = u.p64 + (length / sc_block_size) * sc_num_vars;
	remainder = (uint8_t) (length - (((const uint8_t *) end_p) - u.p8));

	if(ALLOW_UNALIGNED_READS || (u.i & 0x7) == 0)
	{
		while(u.p64 < end_p)
		{
			mix(
				u.p64,
				&s0,
				&s1,
				&s2,
				&s3,
				&s4,
				&s5,
				&s6,
				&s7,
				&s8,
				&s9,
				&s10,
				&s11
			);
			u.p64 += sc_num_vars;
		}
	}
	else
	{
		while(u.p64 < end_p)
		{
			memcpy(state->data,u.p8,sc_block_size);
			mix(
				state->data,
				&s0,
				&s1,
				&s2,
				&s3,
				&s4,
				&s5,
				&s6,
				&s7,
				&s8,
				&s9,
				&s10,
				&s11
			);
			u.p64 += sc_num_vars;
		}
	}

	state->remainder = remainder;
	memcpy(state->data,end_p,remainder);

	state->state[0] = s0;
	state->state[1] = s1;
	state->state[2] = s2;
	state->state[3] = s3;
	state->state[4] = s4;
	state->state[5] = s5;
	state->state[6] = s6;
	state->state[7] = s7;
	state->state[8] = s8;
	state->state[9] = s9;
	state->state[10] = s10;
	state->state[11] = s11;
}

void
spookyhash_final
(
	spookyhash_state_t	*state,
	uint64_t		*hash1,
	uint64_t		*hash2
)
{
	if(state->length < sc_buf_size)
	{
		*hash1 = state->state[0];
		*hash2 = state->state[1];
		spookyhash_short(state->data,state->length,hash1,hash2,state);
		return;
	}

	const uint64_t *data = (const uint64_t *) state->data;
	uint8_t remainder = state->remainder;

	uint64_t h0	= state->state[0];
	uint64_t h1	= state->state[1];
	uint64_t h2	= state->state[2];
	uint64_t h3	= state->state[3];
	uint64_t h4	= state->state[4];
	uint64_t h5	= state->state[5];
	uint64_t h6	= state->state[6];
	uint64_t h7	= state->state[7];
	uint64_t h8	= state->state[8];
	uint64_t h9	= state->state[9];
	uint64_t h10	= state->state[10];
	uint64_t h11	= state->state[11];

	if(remainder >= sc_block_size)
	{
		mix(
			data,
			&h0,
			&h1,
			&h2,
			&h3,
			&h4,
			&h5,
			&h6,
			&h7,
			&h8,
			&h9,
			&h10,
			&h11
		);
		data += sc_num_vars;
		remainder -= sc_block_size;
	}

	memset(&((uint8_t *) data)[remainder],0,(sc_block_size - remainder));

	((uint8_t *) data)[sc_block_size - 1] = remainder;

	end(
		data,
		&h0,
		&h1,
		&h2,
		&h3,
		&h4,
		&h5,
		&h6,
		&h7,
		&h8,
		&h9,
		&h10,
		&h11
	);

	*hash1 = h0;
	*hash2 = h1;
}

void
spookyhash128
(
	const void		*message,
	size_t			 length,
	uint64_t		*hash1,
	uint64_t		*hash2
)
{
	if(length < sc_buf_size)
	{
		spookyhash_short(message,length,hash1,hash2,0);
		return;
	}

	uint64_t s0;
	uint64_t s1;
	uint64_t s2;
	uint64_t s3;
	uint64_t s4;
	uint64_t s5;
	uint64_t s6;
	uint64_t s7;
	uint64_t s8;
	uint64_t s9;
	uint64_t s10;
	uint64_t s11;

	uint64_t buf[sc_num_vars];
	uint64_t *end_p;
	union
	{
		const uint8_t	*p8;
		uint64_t	*p64;
		size_t		 i;
	} u;
	size_t remainder;

	s0 = *hash1;
	s3 = *hash1;
	s6 = *hash1;
	s9 = *hash1;
	s1 = *hash2;
	s4 = *hash2;
	s7 = *hash2;
	s10 = *hash2;
	s2 = sc_const;
	s5 = sc_const;
	s8 = sc_const;
	s11 = sc_const;

	u.p8 = (const uint8_t *) message;
	end_p = u.p64 + (length / sc_block_size) * sc_num_vars;

	if(ALLOW_UNALIGNED_READS || ((u.i & 0x7) == 0))
	{
		while(u.p64 < end_p)
		{
			mix(
				u.p64,
				&s0,
				&s1,
				&s2,
				&s3,
				&s4,
				&s5,
				&s6,
				&s7,
				&s8,
				&s9,
				&s10,
				&s11
			);
			u.p64 += sc_num_vars;
		}
	}
	else
	{
		while(u.p64 < end_p)
		{
			memcpy(buf,u.p64,sc_block_size);
			mix(
				buf,
				&s0,
				&s1,
				&s2,
				&s3,
				&s4,
				&s5,
				&s6,
				&s7,
				&s8,
				&s9,
				&s10,
				&s11
			);
			u.p64 += sc_num_vars;
		}
	}

	remainder = length - (((const uint8_t *) end_p) - ((const uint8_t *) message));
	memcpy(buf,end_p,remainder);
	memset(((uint8_t *) buf) + remainder,0,sc_block_size - remainder);
	((uint8_t *)buf)[sc_block_size - 1] = remainder;

	end(
		buf,
		&s0,
		&s1,
		&s2,
		&s3,
		&s4,
		&s5,
		&s6,
		&s7,
		&s8,
		&s9,
		&s10,
		&s11
	);
	*hash1 = s0;
	*hash2 = s1;
}

uint64_t
spookyhash64
(
	const void		*message,
	size_t			 length,
	uint64_t		 seed
)
{
	uint64_t hash1 = seed;

	spookyhash128(message,length,&hash1,&seed);

	return hash1;
}

uint32_t
spookyhash32
(
	const void		*message,
	size_t			 length,
	uint32_t		 seed
)
{
	uint64_t hash1 = seed;
	uint64_t hash2 = seed;

	spookyhash128(message,length,&hash1,&hash2);

	return (uint32_t) hash1;
}
