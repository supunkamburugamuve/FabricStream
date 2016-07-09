#include <cstdio>
#include <cstdlib>
#include <unistd.h>
#include <cstdlib>
#include <cstring>
#include <iostream>

#include "buffer.h"

Buffer::Buffer(uint64_t buf_size, uint32_t no_bufs) {
	this->buf_size = buf_size;
	this->no_bufs = no_bufs;
	this->head = 0;
	this->tail = 0;
	this->wr_ids = NULL;
	this->content_sizes = NULL;
	this->buffers = NULL;
}

int Buffer::Init(bool align) {
	uint32_t i = 0;
	int alignment = 1;
	int ret;
	this->buffers = (void **)malloc(sizeof(void *) * no_bufs);
	this->content_sizes = (uint64_t *)malloc(sizeof(uint64_t) * no_bufs);
	for (i = 0; i < no_bufs; i++) {
		if (align) {
			alignment = sysconf(_SC_PAGESIZE);
			if (alignment < 0) {
				return 1;
			}
			buf_size += alignment;
			ret = posix_memalign(&this->buffers[i], (size_t) alignment, buf_size);
			if (ret) {
				printf("posix_memalign %d\n", ret);
				return 1;
			}
		} else {
			this->buffers[i] = (void *)malloc(sizeof(uint8_t) * buf_size);
		}
		memset(this->buffers[i], 0, buf_size);
	}
	this->wr_ids = (uint64_t *)malloc(sizeof(uint64_t) * no_bufs);
	this->head = 0;
	this->tail = 0;
	return 0;
}

Buffer::~Buffer() {
}

int Buffer::Increment(int size, int current) {
	return size - 1 == current ? 0 : current + 1;
}

bool Buffer::IncrementHead() {
	uint32_t tail_previous = this->tail == 0 ? this->no_bufs - 1 : this->tail - 1;
	if (this->head != tail_previous) {
		this->head = this->head != this->no_bufs - 1 ? this->head + 1 : 0;
		return true;
	} else {
		return false;
	}
}

bool Buffer::IncrementTail() {
	if (this->head != this->tail) {
		this->tail = this->tail != 0 ? this->tail + 1 : this->no_bufs -1;
		return true;
	} else {
		return false;
	}
}
