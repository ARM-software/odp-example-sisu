/* Copyright 2015, ARM Limited or its affiliates. All rights reserved. */

#ifndef _PPP_MESSAGE_H
#define _PPP_MESSAGE_H

#include <stdint.h>

//Message type, always first in message
typedef uint32_t ppp_msgtype;

//Abstract base class for message structs
//Each module using messages will define this union with the relevant members
union ppp_message;

//Return message to sender
void ppp_msg_return(union ppp_message *msg);

#endif
