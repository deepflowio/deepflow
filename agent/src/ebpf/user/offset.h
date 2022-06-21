#ifndef _BPF_OFFSET_H_
#define _BPF_OFFSET_H_

/* 返回值为偏移量, ETR_INVAL 表示执行过程中出错 */
int struct_member_offset_analyze(const char *bin, const char *structure,
				 const char *member);

#endif
