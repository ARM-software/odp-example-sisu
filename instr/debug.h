/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _DEBUG_H
#define _DEBUG_H

#define FATAL_ERROR(str) do { \
	perror(str), abort(); \
	} while (0)

#define FATAL_ERROR_COND(cond, str) do { \
	if (cond)\
		perror(str), abort(); \
	} while (0)

#ifdef SISU_DEBUG
extern bool only_discarded;

#define DEBUG_BUF_SIZE 100

#define DEBUG(str) \
	printf(str "\n")

#define DEBUG_1(str, par1) \
	printf(str "\n", par1)

#define DEBUG_2(str, par1, par2) \
	printf(str "\n", par1, par2)

#define DEBUG_PKT(str) do { \
	char buf[DEBUG_BUF_SIZE]; \
	snprintf(buf, sizeof(buf), "%s-%s: " str, graph->name, name); \
		pkt->log_add(buf); \
	} while (0)

#define DEBUG_PKT_1(str, par1) do { \
	char buf[DEBUG_BUF_SIZE]; \
	snprintf(buf, sizeof(buf), "%s-%s: " str, graph->name, name, par1); \
		pkt->log_add(buf); \
	} while (0)

#define DEBUG_PKT_2(str, par1, par2) do { \
	char buf[DEBUG_BUF_SIZE]; \
	snprintf(buf, sizeof(buf), "%s-%s: " str, \
		 graph->name, name, par1, par2); \
		 pkt->log_add(buf); \
	} while (0)

#else
#define DEBUG(str)
#define DEBUG_1(str, par1)
#define DEBUG_2(str, par1, par2)
#define DEBUG_PKT(str)
#define DEBUG_PKT_1(str, par1)
#define DEBUG_PKT_2(str, par1, par2)
#endif

#endif
