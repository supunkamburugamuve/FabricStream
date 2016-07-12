#ifndef BUFFER_H_
#define BUFFER_H_

#include <unistd.h>

struct message {
	uint32_t length;
	void *buf;
};

class Buffer {
public:
	Buffer(uint64_t buf_size, uint32_t no_bufs);
	int Init(bool align);
	virtual ~Buffer();
	// increment the head
	bool IncrementHead();
	// increment the tail
	bool IncrementTail();
	// get the free space available in the buffers
	uint64_t GetFreeSpace();
	// get the current buffer, to be used, if this buffer is used
	// the head should be incremented
	void *GetBuffer();
	uint64_t BufferSize();
	uint32_t NoOfBuffers();
	void Free();
private:
	// part of the buffer allocated to this buffer
	void *buf;
	// the list of buffer pointers, these are pointers to
	// part of a large buffer allocated
	void **buffers;
	// list of buffer sizes
	uint64_t buf_size;
	// array of actual data sizes
	uint64_t *content_sizes;
	// wr id for corresponding buffer
	// we need this to keep track of the buffer after a
	// completion is retrieved through cq
	// when sending this needs to be updated
	uint64_t *wr_ids;
	// buffers between tail and head are posted to RDMA operations
	// tail of the buffers that are being used
	// the buffers can be in a posted state, or received messages
	uint32_t tail;
	// head of the buffer
	uint32_t head;
	// buffers between head and data_head are with data from users
	// and these are ready to be posted
	// in case of receive, the data between tail and data_head are
	// received data, that needs to be consumed by the user
	uint32_t data_head;
	// no of buffers
	uint32_t no_bufs;
};

#endif /* BUFFER_H_ */
