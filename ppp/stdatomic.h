/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _STDATOMIC_H
#define _STDATOMIC_H

#include "odp.h"

class atomic_uint16
{
private:
    odp_atomic_u32_t val;//ODP does not provide any 16-bit atomic type
public:
    inline atomic_uint16()
    {
	odp_atomic_init_u32(&val, 0);
    }
    inline atomic_uint16(uint16_t i)
    {
	odp_atomic_init_u32(&val, i);
    }
    inline uint16_t get_add(uint16_t i)
    {
	uint32_t old = odp_atomic_fetch_add_u32(&val, i);
	return static_cast<uint16_t>(old);
    }
};

class atomic_uint32
{
private:
    odp_atomic_u32_t val;
public:
    inline atomic_uint32()
    {
	odp_atomic_init_u32(&val, 0);
    }
    inline atomic_uint32(uint32_t i)
    {
	odp_atomic_init_u32(&val, i);
    }
    inline void set(uint32_t v)
    {
	odp_atomic_store_u32(&val, v);
    }
    inline uint32_t get()
    {
	return odp_atomic_load_u32(&val);
    }
    inline void add(uint32_t i)
    {
	odp_atomic_add_u32(&val, i);
    }
    inline uint32_t get_add(uint32_t i)
    {
	return odp_atomic_fetch_add_u32(&val, i);
    }
};

class atomic_uint64
{
private:
    odp_atomic_u64_t val;
public:
    inline atomic_uint64()
    {
	odp_atomic_init_u64(&val, 0);
    }
    inline atomic_uint64(uint64_t i)
    {
	odp_atomic_init_u64(&val, i);
    }
    inline void set(uint64_t v)
    {
	odp_atomic_store_u64(&val, v);
    }
    inline uint64_t get()
    {
	return odp_atomic_load_u64(&val);
    }
    inline void add(uint64_t i)
    {
	odp_atomic_add_u64(&val, i);
    }
};

#endif //_STDATOMIC_H
