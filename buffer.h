#ifndef BUFFER_H_
#define BUFFER_H_

#include <unistd.h>

struct message {
	uint32_t length;
	void *buf;
};

class Buffer {
public:
	Buffer(void *buf, uint64_t buf_size, uint32_t no_bufs);
	int Init(bool align);
	virtual ~Buffer();
	// increment the head
	bool IncrementHead();
	// increment the tail
	bool IncrementTail();
	// increment the data head
	bool IncrementDataHead();
	// get the free space available in the buffers
	uint64_t GetFreeSpace();
	// get the space ready to be received by user
	uint64_t GetReceiveReadySpace();
	// get space ready to be posted to Hardware
	uint64_t GetSendReadySpace();
	// get the current buffer, to be used, if this buffer is used
	// the head should be incremented
	inline void* GetBuffer(int i) {
		return buffers[i];
	}
	inline int64_t BufferSize() {
		return buf_size;
	};

	inline uint32_t NoOfBuffers() {
		return no_bufs;
	}

	inline uint32_t Head() {
		return head;
	}

	inline uint32_t Tail() {
		return tail;
	}

	inline uint32_t DataHead() {
		return data_head;
	}

	inline uint32_t ContentSize(int i) {
		return content_sizes[i];
	}

	inline void SetDataHead(uint32_t head) {
		this->data_head = head;
	}

	inline void SetHead(uint32_t head) {
		this->head = head;
	}

	inline void SetTail(uint32_t tail) {
		this->tail = tail;
	}

	void Free();
private:
	// part of the buffer allocated to this buffer
	void *buf;
	// the list of buffer pointers, these are pointers to
	// part of a large buffer allocated
	void **buffers;
	// list of buffer sizes
	uint32_t buf_size;
	// array of actual data sizes
	uint32_t *content_sizes;
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
