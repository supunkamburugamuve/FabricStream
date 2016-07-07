/*
 * buffer.cpp
 *
 *  Created on: Jul 6, 2016
 *      Author: supun
 */

#include "buffer.h"

Buffer::Buffer(uint32_t buf_size, uint32_t no_bufs) {
	// TODO Auto-generated constructor stub
	int i = 0;
	this->no_bufs = no_bufs;
	this->buffers = (uint8_t *)malloc(sizeof(uint8_t *) * no_bufs);
	this->sizes = (uint64_t *)malloc(sizeof(uint64_t) * no_bufs);
	this->content_sizes = (uint64_t *)malloc(sizeof(uint64_t) * no_bufs);
	for (i = 0; i < no_bufs; i++) {
		this->buffers[i] = malloc(sizeof(uint8_t) * buf_size);
	}
	this->wr_ids = malloc(sizeof(uint64_t) * no_bufs);
	this->head = 0;
	this->tail = 0;
}

Buffer::~Buffer() {
}

int Buffer::Increment(int size, int current) {
	return size - 1 == current ? 0 : current + 1;
}

int Buffer::IncrementHead() {
	int tail_previous = this->tail == 0 ? this->no_bufs - 1 : this->tail - 1;
	if (this->head != tail_previous) {
		this->head = this->head != this->no_bufs - 1 ? this->head + 1 : 0;
		return 0;
	} else {
		return 1;
	}
}

int Buffer::IncrementTail() {
	if (this->head != this->tail) {
		this->tail = this->tail != 0 ? this->tail + 1 : this->no_bufs -1;
		return 0;
	} else {
		return 1;
	}
}
