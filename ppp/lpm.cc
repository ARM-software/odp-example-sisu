/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#include <stdbool.h>
#include <assert.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <math.h>
#include "compiler.h"
#include "lpm.h"

#define IP2NdNdNdN(x) (x) >> 24, ((x) >> 16) & 0xff, ((x) >> 8) & 0xff, (x) & 0xff

#define MAX(a,b) ((a) > (b) ? (a) : (b))

#define STARTS(n) ((n)->dest)
#define ENDS(n) ((n)->dest + ~(n)->mask)

static bool option_f;

void insert_prefix(prefix **parent_ptr, prefix *newn);

#ifndef NDEBUG
//static uint32_t len_from_mask(uint32_t mask) __attribute((noinline));
static uint32_t len_from_mask(uint32_t mask)
{
    return mask != 0U ? 33U - ffs(mask) : 0U;
}
#endif

//static uint32_t mask_from_len(uint32_t len) __attribute((noinline));
static uint32_t mask_from_len(uint32_t len)
{
#if 0
    return ~((1U << (32U - len)) - 1U);
#else //above doesn't work as expected on x86 with gcc 4.8.1
    return len != 0U ? ~((1U << (32U - len)) - 1U) : 0U;
#endif
}

uint32_t _depth(const prefix *node, uint32_t masklen)
{
    if (unlikely(node == NULL))
    {
	return 0;
    }
    if (!option_f)
    {
	if (node->masklen != masklen)
	{
	    return 0;
	}
    }
    return node->depth;
}

#ifndef DNDEBUG
void
assert_limits(const prefix *thiz, const prefix *const root, enum l_type type)
{
    assert(STARTS(thiz) <= ENDS(thiz));
    assert(thiz->masklen >= root->masklen);
    switch (type)
    {
	case l_before :
	    assert(ENDS(thiz) < STARTS(root));
	    break;
	case l_within :
	    assert(STARTS(thiz) >= STARTS(root) && ENDS(thiz) <= ENDS(root));
	    break;
	case l_after :
	    assert(STARTS(thiz) > ENDS(root));
	    break;
    }
    if (thiz->before != NULL)
	assert_limits(thiz->before, root, type);
    if (thiz->after != NULL)
	assert_limits(thiz->after, root, type);
    if (thiz->within != NULL)
	assert_limits(thiz->within,  root, type);
}

void
assert_prefix(const prefix *thiz)
{
    if (thiz == NULL)
    {
	return;
    }

    assert(len_from_mask(thiz->mask) == thiz->masklen);
    assert(mask_from_len(thiz->masklen) == thiz->mask);

    //Verify that all children conform to our start/end limits
    if (thiz->before != NULL)
    {
	assert(thiz->before->masklen >= thiz->masklen);
	assert_limits(thiz->before, thiz, l_before);
	assert_prefix(thiz->before);
    }
    if (thiz->after != NULL)
    {
	assert(thiz->after->masklen >= thiz->masklen);
	assert_limits(thiz->after, thiz, l_after);
	assert_prefix(thiz->after);
    }
    if (thiz->within != NULL)
    {
	assert(thiz->within->masklen > thiz->masklen);
	assert_limits(thiz->within, thiz, l_within);
	assert_prefix(thiz->within);
    }
}
#else
#define assert_prefix(x) (void)(x)
#endif

prefix::prefix(uint32_t _dest, uint8_t _len)
{
    before = NULL;
    within = NULL;
    after = NULL;
    dest = _dest;
    mask = mask_from_len(_len);
    masklen = _len;
    depth = 1U;
    assert_prefix(this);
}

void rebalance(prefix **parent_ptr)
{
    prefix *A = *parent_ptr;
    int bal = _depth(A->before, A->masklen) - _depth(A->after, A->masklen);
    if (bal < -1) //DEPTH(before) << DEPTH(AFTER), new node inserted on right side
    {
	prefix *C = A->after;
	if (_depth(C->before, C->masklen) > _depth(C->after, C->masklen))
	{
	    if (option_f && !C->ok_to_rotate_right()) goto skip;
	    A->after = A->after->rotate_right();
	}
	if (option_f && !A->ok_to_rotate_left()) goto skip;
	*parent_ptr = A->rotate_left();
    }
    else if (bal > 1) //DEPTH(before) >> DEPTH(after), new node inserted on left side
    {
	prefix *B = A->before;
	if (_depth(B->after, B->masklen) > _depth(B->before, B->masklen))
	{
	    if (option_f && !B->ok_to_rotate_left()) goto skip;
	    A->before = A->before->rotate_left();
	}
	if (option_f && !A->ok_to_rotate_right()) goto skip;
	*parent_ptr = A->rotate_right();
    }
skip:
    (void)0;
}

static unsigned n_moved;

void
insert_subtree(prefix **parent_ptr, prefix *node)
{
    //Read pointers to outside children before the fields are cleared
    //Inside children are already in the right place
    assert_prefix(node);
    prefix *before = node->before;
    prefix *after = node->after;
    node->before = node->after = NULL;
    node->depth = node->compute_depth();
    assert_prefix(node);
n_moved++;
    insert_prefix(parent_ptr, node);
    assert_prefix(node);
    assert_prefix(*parent_ptr);
    //Now re-insert the outside children
    if (before != NULL)
    {
	assert_prefix(before);
	insert_subtree(parent_ptr, before);
    }
    if (after != NULL)
    {
	assert_prefix(after);
	insert_subtree(parent_ptr, after);
    }
}

void
insert_prefix(prefix **parent_ptr, prefix *newn) __attribute((noinline));
void
insert_prefix(prefix **parent_ptr, prefix *newn)
{
    prefix *curn = *parent_ptr;
    if (unlikely(curn == NULL))
    {
	newn->before = NULL;
	newn->after = NULL;
	newn->depth = 1;
	//Leave inside pointer as is
	*parent_ptr = newn;
	assert_prefix(newn);
    }
    else if (likely(newn->masklen >= curn->masklen))
    {
	//Insert new node below current node
	if (STARTS(newn) < STARTS(curn))
	{
	    assert(ENDS(newn) < STARTS(curn));
	    insert_prefix(&curn->before, newn);
	}
	else if (STARTS(newn) > ENDS(curn))
	{
	    assert(STARTS(newn) > ENDS(curn));
	    insert_prefix(&curn->after, newn);
	}
	else
	{
	    assert(STARTS(newn) >= STARTS(curn));
	    assert(ENDS(newn) <= ENDS(curn));
	    if (newn->masklen > curn->masklen)
	    {
		insert_prefix(&curn->within, newn);
	    }
	    else
	    {
		assert(STARTS(newn) == STARTS(curn));
		assert(ENDS(newn) == ENDS(curn));
		//Duplicate prefix
		fprintf(stderr, "Ignoring duplicate prefix %u.%u.%u.%u/%u",
			IP2NdNdNdN(newn->dest), newn->masklen);
	    }
	    return;
	}
	if (curn->recompute_depth())
	{
	    rebalance(parent_ptr);
	}
    }
    else//if (newn->masklen < curn->masklen)
    {
	assert(newn->masklen < curn->masklen);
	//Insert new node above current node to preserve masklen ordering
	prefix *to_move;
	if (STARTS(curn) < STARTS(newn))
	{
	    assert(ENDS(curn) < STARTS(newn));
	    *parent_ptr = newn;
	    newn->before = curn;
	    newn->after = NULL;
	    //Prefixes after curn might have to be moved
	    to_move = curn->after;
	    curn->after = NULL;
	    if (curn->recompute_depth())
	    {
		rebalance(&newn->before);
	    }
	    if ((*parent_ptr)->recompute_depth())
	    {
		rebalance(parent_ptr);
	    }
	}
	else if (STARTS(curn) > ENDS(newn))
	{
	    *parent_ptr = newn;
	    newn->before = NULL;
	    newn->after = curn;
	    //Prefixes before curn might need to be moved
	    to_move = curn->before;
	    curn->before = NULL;
	    if (curn->recompute_depth())
	    {
		rebalance(&newn->after);
	    }
	    if ((*parent_ptr)->recompute_depth())
	    {
		rebalance(parent_ptr);
	    }
	}
	else//Within
	{
	    abort();
	}
	assert_prefix(newn);
	if (to_move != NULL)
	{
	    insert_subtree(parent_ptr, to_move);
	}
	assert_prefix(newn);
    }
    if (!option_f)
    {
	prefix *root = *parent_ptr;
	int balance = _depth(root->before, root->masklen) -
		      _depth(root->after, root->masklen);
	assert(balance >= -1 && balance <= 1);
	(void)balance;
    }
}

void
prefix::traverse(void (*apply)(prefix *, void *), void *arg)
{
    if (before != NULL)
    {
	before->traverse(apply, arg);
    }
    if (within != NULL)
    {
	within->traverse(apply, arg);
    }
    apply(this, arg);
    if (after != NULL)
    {
	after->traverse(apply, arg);
    }
}

unsigned
prefix::count_nodes(unsigned histo_ch[3],
		    const unsigned depth,
		    unsigned histo_dep[])
{
    uint32_t my_children = 0, all_nodes = 0;
    if (before != NULL)
    {
	my_children++;
	all_nodes += before->count_nodes(histo_ch, depth + 1, histo_dep);
    }
    if (within != NULL)
    {
	//	    my_children++;//Longer prefix matches don't count as children
	all_nodes += within->count_nodes(histo_ch, depth + 1, histo_dep);
    }
    if (after != NULL)
    {
	my_children++;
	all_nodes += after->count_nodes(histo_ch, depth + 1, histo_dep);
    }
    if (my_children == 0)
    {
	histo_dep[0]++;//Number of leaves
	histo_dep[depth]++;//Another leaf node with thiz depth
    }
    histo_ch[my_children]++;
    return 1 + all_nodes;//Number of nodes in subtree including thiz
}

char *
prefix::prefix2label(char buf[32]) const
{
    sprintf(buf, "%u.%u.%u.%u/%u", IP2NdNdNdN(dest), masklen);
    return buf;
}

static int override_length = -1;

void
prefix::printdot(FILE *file, const prefix *parent) const
{
    char label[32];
    const char *color;
    if (parent == NULL)
	color = "black";
    else if (parent->before == this)
	color = "blue";
    else if (parent->within == this)
	color = "green";
    else if (parent->after == this)
	color = "red";
    else
	abort();
    if (override_length == this->masklen)
	color = "magenta";
    prefix2label(label);

    fprintf(file, "t%lx [label=\"%s\" color=%s shape=diamond]\n",
	    (long)this, label, color);
    if (this->before != NULL)
    {
	fprintf(file, "t%lx -> t%lx [label=\"before\" color=blue]\n",
		(long)this, (long)this->before);
	this->before->printdot(file, this);
    }
    if (this->within != NULL)
    {
	fprintf(file, "t%lx -> t%lx [label=\"within\" color=green]\n",
		(long)this, (long)this->within);
	this->within->printdot(file, this);
    }
    if (this->after != NULL)
    {
	fprintf(file, "t%lx -> t%lx [label=\"after\" color=red]\n",
		(long)this, (long)this->after);
	this->after->printdot(file, this);
    }
}

//dot -Tps prefix.dot > prefix.ps && evince prefix.ps
void
prefix_tree::generate_dot(const char *filename, const char *title)
{
    FILE *file;
    file = fopen(filename, "w");
    if (file == NULL)
    {
	perror("fopen"), exit(EXIT_FAILURE);
    }
    if (fprintf(file, "digraph routing_table\n{\n") < 0)
    {
	perror("fprintf"), exit(EXIT_FAILURE);
    }
    if (root != NULL)
    {
	root->printdot(file, NULL);
    }
    fprintf(file, "title [label=\"title=%s\" shape=box]\n", title);
    if (fprintf(file, "}\n") < 0)
    {
	perror("fprintf"), exit(EXIT_FAILURE);
    }
    if (fclose(file) != 0)
    {
	perror("fclose"), exit(EXIT_FAILURE);
    }
}

prefix *
prefix_tree::find_lpm(uint32_t addr)
{
#if 0
    printf("Looking up address %u.%u.%u.%u -> ", IP2NdNdNdN(addr));
#endif
    prefix *lpm = NULL;//Best match so far
    prefix *node = root;
    while (likely(node != NULL))
    {
	prefix *before = node->before;//Preload before if
	prefix *after = node->after;//Preload before if
	if (likely(addr - node->dest > ~node->mask))
	{
	    assert(addr < STARTS(node) || addr > ENDS(node));
	    assert(((addr ^ node->dest) & node->mask) != 0);
	    node = addr < node->dest ? before : after;
	}
	else
	{
	    assert(addr >= STARTS(node) && addr <= ENDS(node));
	    assert(((addr ^ node->dest) & node->mask) == 0);
	    lpm = node;
	    node = node->within;
	}
    }
#if 0
    if (lpm != NULL)
    {
	char buf[100];
	printf("%s\n", lpm->prefix2label(buf));
    }
    else
    {
	printf("\n");
    }
#endif
    return lpm;
}

void
prefix_tree::add_prefix(prefix *pfx)
{
    insert_prefix(&root, pfx);
}

void
prefix_tree::traverse(void (*apply)(prefix *, void *), void *arg)
{
    if (root != NULL)
    {
	root->traverse(apply, arg);
    }
}

float
prefix_tree::print_histo()
{
    unsigned histo_ch[3], histo_dep[1000];
    histo_ch[0] = histo_ch[1] = histo_ch[2] = 0;
    memset(histo_dep, 0, sizeof histo_dep);
    unsigned nodes = root ? root->count_nodes(histo_ch, 1, histo_dep) : 0;
    printf("Children 0:%u 1:%u 2:%u\n", histo_ch[0], histo_ch[1], histo_ch[2]);

    //Compute histogram over depths of leaf nodes (not internal nodes)
    unsigned sum = 0;
    for (int i = 1; i < 1000; i++)
    {
	if (histo_dep[i] != 0)
	{
	    printf("%u: %u\n", i, histo_dep[i]);
	    sum += i * histo_dep[i];
	}
    }
    //histo_dep[0] contains number of leaves
    float avg = (float)sum / histo_dep[0];
    printf("Max depth: %u, average depth: %.2f, log2(%u)=%.2f\n",
	   root->depth, avg, nodes, log(nodes) / log(2.0));
    return avg;
}
