/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _LPM_H
#define _LPM_H

#include <cstdio>
#include <stdint.h>

enum l_type
{
    l_before, l_within, l_after
};

class prefix_tree;

class prefix
{
private:
    prefix *before; //#0
    prefix *after;  //#4
    prefix *within; //#8
public:
    uint32_t dest;      //#12
    uint32_t mask;      //#16
    uint16_t masklen;   //#20
private:
    uint16_t depth;     //#22
public:
    prefix(uint32_t _dest, uint8_t _len);
    void traverse(void (*apply)(prefix *, void *), void *arg);
    void printdot(FILE *file, const prefix *parent) const;
    char *prefix2label(char buf[32]) const;

private:
    friend uint32_t _depth(const prefix *node, uint32_t masklen);
    uint32_t compute_depth() const
    {
	uint32_t d_b = _depth(before, masklen);
	uint32_t d_a = _depth(after, masklen);
	return d_b > d_a ? d_b : d_a;
    }
    bool recompute_depth()
    {
	uint32_t old_depth = depth;
	depth = 1 + compute_depth();
	return old_depth != depth;
    }
    bool ok_to_rotate_right() const
    {
	if (before != NULL)
	{
	    return masklen == before->masklen;
	}
	return false;
    }
    bool ok_to_rotate_left() const
    {
	if (after != NULL)
	{
	    return masklen == after->masklen;
	}
	return false;
    }
    prefix *rotate_right() //A->before becomes new root
    {
	prefix *A = this;
	assert(A->ok_to_rotate_right());
	prefix *B = A->before;
	assert(B->masklen <= A->masklen);
	A->before = B->after;
	(void)A->recompute_depth();
	B->after = A;
	(void)B->recompute_depth();
	assert_prefix(B);
	return B;
    }
    prefix *rotate_left() //A->after becomes new root
    {
	prefix *A = this;
	assert(A->ok_to_rotate_left());
	prefix *C = A->after;
	assert(C->masklen <= A->masklen);
	A->after = C->before;
	(void)A->recompute_depth();
	C->before = A;
	(void)C->recompute_depth();
	assert_prefix(C);
	return C;
    }

    unsigned count_nodes(unsigned histo_ch[3],
			 const unsigned depth,
			 unsigned histo_dep[]);
    //Assert functions are compile-time conditional so not member functions
    friend void assert_limits(const prefix *thiz,
			      const prefix *const root,
			      enum l_type type);
    friend void assert_prefix(const prefix *thiz);

    //Update operations take a parent_ptr so cannot be member functions
    friend void rebalance(prefix **parent_ptr);
    friend void insert_subtree(prefix **parent_ptr, prefix *node);
    friend void insert_prefix(prefix **parent_ptr, prefix *node);

    friend class prefix_tree;
};

class prefix_tree
{
private:
    prefix *root;
public:
    prefix_tree()
    {
	root = NULL;
    }
    void add_prefix(prefix *pfx);
    prefix *find_lpm(uint32_t addr);
    void traverse(void (*apply)(prefix *, void *arg), void *arg);
    float print_histo();
    void generate_dot(const char *filename, const char *title);
};

#endif //_LPM_H
