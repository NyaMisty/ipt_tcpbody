/* TCP window modification module for IP tables
 * (C) 2015 by Sergej Pupykin <sergej@p5n.pp.ru> */

#ifndef _IPT_TBODY_H
#define _IPT_TBODY_H

#include <linux/types.h>

struct ipt_TBODY_info {
	__u16	bodylen;
};

#endif
