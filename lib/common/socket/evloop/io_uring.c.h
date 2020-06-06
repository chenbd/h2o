/*
 * Copyright (c) 2020 Baodong Chen
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 */
#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/poll.h>
#include <liburing.h>

#if 0
#define DEBUG_LOG(...) h2o_error_printf(__VA_ARGS__)
#else
#define DEBUG_LOG(...)
#endif

#ifndef IO_URING_QUEUE_DEPTH
#define IO_URING_QUEUE_DEPTH 4096 /* kernel's 'IORING_MAX_ENTRIES' is 32768 */
#endif

#define SQE_USER_DATA_POLL 0x0ul
#define SQE_USER_DATA_READ 0x1ul
#define SQE_USER_DATA_WRITE 0x2ul

#define USER_DATA_TO_SOCK(user_data) ((void *)((user_data) & ~0x03ul))
#define USER_DATA_IS_POLL(user_data) (((user_data)&0x03ul) == SQE_USER_DATA_POLL)
#define USER_DATA_IS_READ(user_data) (((user_data)&0x03ul) == SQE_USER_DATA_READ)
#define USER_DATA_IS_WRITE(user_data) (((user_data)&0x03ul) == SQE_USER_DATA_WRITE)

struct st_h2o_evloop_io_uring_t {
    h2o_evloop_t super;
    struct io_uring ring;
    uint64_t total_sqe;
    uint64_t total_cqe;
};

static void __poll_add(struct st_h2o_evloop_socket_t *sock, short poll_mask)
{
    struct st_h2o_evloop_io_uring_t *loop = (void *)sock->loop;
    struct io_uring_sqe *sqe;

    sqe = io_uring_get_sqe(&loop->ring);
    assert(sqe);
    DEBUG_LOG("loop:%p poll_add sqe: %p, sock: %p\n", loop, sqe, sock);
    if (sqe) {
        io_uring_prep_poll_add(sqe, sock->fd, poll_mask);
        io_uring_sqe_set_data(sqe, (unsigned long)sock | SQE_USER_DATA_POLL);
    } else {
        // TODO: If the SQ ring is full?
    }
}

static void __poll_remove(struct st_h2o_evloop_socket_t *sock)
{
    struct st_h2o_evloop_io_uring_t *loop = (void *)sock->loop;
    struct io_uring_sqe *sqe;

    sqe = io_uring_get_sqe(&loop->ring);
    assert(sqe);
    DEBUG_LOG("loop:%p poll_rm sqe: %p, sock: %p\n", loop, sqe, sock);
    if (sqe) {
        io_uring_prep_poll_remove(sqe, (unsigned long)sock | SQE_USER_DATA_POLL);
        /* user_data is zero */
    } else {
        // TODO: If the SQ ring is full?
    }
}

static int update_status(struct st_h2o_evloop_io_uring_t *loop)
{
    while (loop->super._statechanged.head != NULL) {
        /* detach the top */
        struct st_h2o_evloop_socket_t *sock = loop->super._statechanged.head;
        loop->super._statechanged.head = sock->_next_statechanged;
        sock->_next_statechanged = sock;
        /* update the state */
        if ((sock->_flags & H2O_SOCKET_FLAG_IS_DISPOSED) != 0) {
            free(sock);
        } else {
            int changed = 0;
            short poll_mask = 0;
            if (h2o_socket_is_reading(&sock->super)) {
                poll_mask |= EPOLLIN;
                if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_READ) == 0) {
                    sock->_flags |= H2O_SOCKET_FLAG_IS_POLLED_FOR_READ;
                    changed = 1;
                }
            } else {
                if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_READ) != 0) {
                    sock->_flags &= ~H2O_SOCKET_FLAG_IS_POLLED_FOR_READ;
                    changed = 1;
                }
            }
            if (h2o_socket_is_writing(&sock->super)) {
                poll_mask |= EPOLLOUT;
                if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE) == 0) {
                    sock->_flags |= H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE;
                    changed = 1;
                }
            } else {
                if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE) != 0) {
                    sock->_flags &= ~H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE;
                    changed = 1;
                }
            }
            if (changed) {
                if (sock->_flags & H2O_SOCKET_FLAG__IO_URING_IS_POLLING != 0) {
                    __poll_remove(sock);
                    sock->_flags &= ~H2O_SOCKET_FLAG__IO_URING_IS_POLLING;
                }
            }
            if (poll_mask) {
                __poll_add(sock, poll_mask);
                sock->_flags |= H2O_SOCKET_FLAG__IO_URING_IS_POLLING;
            }
        }
    }
    loop->super._statechanged.tail_ref = &loop->super._statechanged.head;

    return 0;
}

int evloop_do_proceed(h2o_evloop_t *_loop, int32_t max_wait)
{
    struct st_h2o_evloop_io_uring_t *loop = (struct st_h2o_evloop_io_uring_t *)_loop;
    struct io_uring_cqe *cqe;
    int ret;

    /* collect (and update) status */
    if (update_status(loop) != 0)
        return -1;

    /* wait for cqes become available */
    max_wait = adjust_max_wait(&loop->super, max_wait);
    if (max_wait < 0) {
        /* tell kernel we have put sqes on the submission ring */
        io_uring_submit(&loop->ring);
        ret = io_uring_wait_cqe_timeout(&loop->ring, &cqe, NULL);
    } else {
        struct timespec ts = {
            .tv_sec = max_wait / 1000,
            .tv_nsec = (max_wait % 1000) * 1000000,
        };
        /**
         * note:
         * 'ts' is specified, the application need not call io_uring_submit() before
         * calling this function
         */
        ret = io_uring_wait_cqe_timeout(&loop->ring, &cqe, &ts);
    }
    DEBUG_LOG("wait ret: %d\n", ret);
    update_now(&loop->super);

    if (!cqe)
        return 0;

    h2o_sliding_counter_start(&loop->super.exec_time_nanosec_counter, loop->super._now_nanosec);

    /* check how many cqes are on the cqe ring, and put these cqes in an array */
    struct io_uring_cqe *cqes[512];
    unsigned cqe_count = io_uring_peek_batch_cqe(&ring, cqes, sizeof(cqes) / sizeof(cqes[0]));
    unsigned i;

    for (i = 0; i < cqe_count; ++i) {
        struct io_uring_cqe *cqe = cqes[i];
        uint64_t user_data = cqe->user_data;
        if (user_data == LIBURING_UDATA_TIMEOUT) {
            DEBUG_LOG("timed out\n");
        } else if (user_data) {
            struct st_h2o_evloop_socket_t *sock = USER_DATA_TO_SOCK(user_data);
            assert(sock);
            DEBUG_LOG("sock flags: 0x%x cqe[res: %d flags: 0x%x]", sock->_flags, cqe->res, cqe->flags);
            if (USER_DATA_IS_POLL(user_data)) {
                if (sock->_flags & H2O_SOCKET_FLAG__IO_URING_IS_POLLING != 0) {
                    sock->_flags &= ~H2O_SOCKET_FLAG__IO_URING_IS_POLLING;

                    if ((cqe->res & (POLLIN | POLLHUP | POLLERR)) != 0) {
                        if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_READ) != 0) {
                            sock->_flags |= H2O_SOCKET_FLAG_IS_READ_READY;
                            link_to_pending(sock);
                        }
                    }
                    if ((cqe->res & (POLLOUT | POLLHUP | POLLERR)) != 0) {
                        if ((sock->_flags & H2O_SOCKET_FLAG_IS_POLLED_FOR_WRITE) != 0) {
                            write_pending(sock);
                        }
                    }
                }
            } else if (USER_DATA_IS_READ(user_data)) {
                ssize_t bytes_read = cqe->res;
                async_on_read_core(sock, bytes_read)
            } else if (USER_DATA_IS_WRITE(user_data)) {
                ssize_t bytes_written = cqe->res;
                async_on_write_core(sock, bytes_written)
            } else {
                DEBUG_LOG("not handled\n");
            }
        }
        /* Mark this request as processed */
        io_uring_cqe_seen(&loop->ring, cqe);
    }

    return 0;
}

static void evloop_do_on_socket_create(struct st_h2o_evloop_socket_t *sock)
{
}

static void evloop_do_on_socket_close(struct st_h2o_evloop_socket_t *sock)
{
    struct st_h2o_evloop_io_uring_t *loop = (void *)sock->loop;
    int ret;

    if (sock->fd == -1)
        return;
    if ((sock->_flags & H2O_SOCKET_FLAG__IO_URING_IS_POLLING) == 0)
        return;

    __poll_remove(sock);
    sock->_flags &= ~H2O_SOCKET_FLAG__IO_URING_IS_POLLING;
}

static void evloop_do_on_socket_export(struct st_h2o_evloop_socket_t *sock)
{
    struct st_h2o_evloop_io_uring_t *loop = (void *)sock->loop;
    int ret;

    if ((sock->_flags & H2O_SOCKET_FLAG__IO_URING_IS_POLLING) == 0)
        return;

    __poll_remove(sock);
    sock->_flags &= ~H2O_SOCKET_FLAG__IO_URING_IS_POLLING;
}

static int evloop_async_write(struct st_h2o_evloop_socket_t *sock, h2o_iovec_t *iov, size_t cnt)
{
    struct st_h2o_evloop_io_uring_t *loop = (void *)sock->loop;
    struct io_uring_sqe *sqe;

    sqe = io_uring_get_sqe(&loop->ring);
    assert(sqe);
    DEBUG_LOG("loop:%p write sqe: %p, sock: %p\n", loop, sqe, sock);
    if (sqe) {
        io_uring_prep_writev(sqe, sock->fd, (const struct iovec *)iov, cnt, 0);
        io_uring_sqe_set_data(sqe, (unsigned long)sock | SQE_USER_DATA_WRITE);
        return 0;
    }
    // TODO: If the SQ ring is full?
    return -1;
}

static int evloop_async_read(struct st_h2o_evloop_socket_t *sock, h2o_iovec_t *iov, size_t cnt)
{
    struct st_h2o_evloop_io_uring_t *loop = (void *)sock->loop;
    struct io_uring_sqe *sqe;

    sqe = io_uring_get_sqe(&loop->ring);
    assert(sqe);
    DEBUG_LOG("loop:%p read sqe: %p, sock: %p\n", loop, sqe, sock);
    if (sqe) {
        io_uring_prep_readv(sqe, sock->fd, (const struct iovec *)iov, cnt, 0);
        io_uring_sqe_set_data(sqe, (unsigned long)sock | SQE_USER_DATA_READ);
        return 0;
    }
    // TODO: If the SQ ring is full?
    return -1;
}

static void evloop_do_dispose(h2o_evloop_t *_loop)
{
    struct st_h2o_evloop_io_uring_t *loop = (struct st_h2o_evloop_io_uring_t *)_loop;
    DEBUG_LOG("disposing loop:%p\n", loop);
    io_uring_queue_exit(loop->ring);
}

h2o_evloop_t *h2o_evloop_create(void)
{
    struct st_h2o_evloop_io_uring_t *loop = (struct st_h2o_evloop_io_uring_t *)create_evloop(sizeof(*loop));

    int ret = io_uring_queue_init(IO_URING_QUEUE_DEPTH, &loop->ring, IORING_SETUP_IOPOLL IORING_SETUP_CLAMP);
    if (ret < 0) {
        h2o_fatal("io_uring_queue_init error(%d)\n", errno);
    }
    DEBUG_LOG("loop: %p created.\n", loop);
    return &loop->super;
}
