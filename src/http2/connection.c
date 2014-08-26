#include <stdio.h>
#include <stdlib.h>
#include "h2o.h"
#include "h2o/http1.h"
#include "h2o/http2.h"
#include "internal.h"

static const uv_buf_t CONNECTION_PREFACE = { H2O_STRLIT("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n") };

static const h2o_http2_settings_t HOST_SETTINGS = {
    /* header_table_size = */ 4096,
    /* enable_push = */ 0,
    /* max_concurrent_streams = */ 100,
    /* initial_window_size = */ 0x7fffffff,
    /* max_frame_size = */ 16384
};

static const uv_buf_t HOST_SETTINGS_BIN = {
    H2O_STRLIT(
        "\x00\x00\x0c" /* frame size */
        "\x04" /* settings frame */
        "\x00" /* no flags */
        "\x00\x00\x00\x00" /* stream id */
        "\x00\x02" "\x00\x00\x00\x00" /* enable_push = 0 */
        "\x00\x03" "\x00\x00\x00\x64" /* max_concurrent_streams = 100 */
    )
};

static ssize_t expect_default(h2o_http2_conn_t *conn, const uint8_t *src, size_t len);

void h2o_http2_conn_register_stream(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    khiter_t iter;
    int r;

    assert(conn->max_open_stream_id < stream->stream_id);
    conn->max_open_stream_id = stream->stream_id;

    iter = kh_put(h2o_http2_stream_t, conn->open_streams, stream->stream_id, &r);
    assert(iter != kh_end(conn->open_streams));
    kh_val(conn->open_streams, iter) = stream;
}

void h2o_http2_conn_unregister_stream(h2o_http2_conn_t *conn, uint32_t stream_id)
{
    khiter_t iter = kh_get(h2o_http2_stream_t, conn->open_streams, stream_id);
    assert(iter != kh_end(conn->open_streams));
    kh_del(h2o_http2_stream_t, conn->open_streams, iter);
}

static void close_connection_now(h2o_http2_conn_t *conn)
{
    h2o_http2_stream_t *stream;

    kh_foreach_value(conn->open_streams, stream, {
        h2o_http2_stream_close(conn, stream);
    });
    kh_destroy(h2o_http2_stream_t, conn->open_streams);
    free(conn->_input);
    assert(conn->_http1_req_input == NULL);
    h2o_mempool_clear(&conn->_write.pool);
    assert(! h2o_timeout_entry_is_linked(&conn->_write.timeout_entry));
    conn->close_cb(conn);
}

static void close_connection(h2o_http2_conn_t *conn)
{
    assert(conn->state != H2O_HTTP2_CONN_STATE_IS_CLOSING);
    conn->state = H2O_HTTP2_CONN_STATE_IS_CLOSING;

    if (conn->_write.bufs.size == 0) {
        assert(conn->_write.flushed_streams == NULL);
        close_connection_now(conn);
    } else {
        /* there is a pending write, let on_write_complete actually close the connection */
    }
}

static void enqueue_goaway_and_initiate_close(h2o_http2_conn_t *conn, int errnum)
{
    uv_buf_t goaway = h2o_http2_encode_goaway_frame(&conn->_write.pool, conn->max_processed_stream_id, -errnum);
    h2o_http2_conn_enqueue_write(conn, goaway);
    conn->state = H2O_HTTP2_CONN_STATE_IS_CLOSING;
}

static void gracefully_shutdown_if_possible(h2o_http2_conn_t *conn)
{
    assert(conn->state == H2O_HTTP2_CONN_STATE_RECVED_GOAWAY);
    if (kh_size(conn->open_streams) != 0)
        return;
    enqueue_goaway_and_initiate_close(conn, 0);
}

static void send_error(h2o_http2_conn_t *conn, uint32_t stream_id, int errnum)
{
    assert(conn->state != H2O_HTTP2_CONN_STATE_IS_CLOSING);

    if (stream_id != 0) {
        uv_buf_t rst_frame = h2o_http2_encode_rst_stream_frame(&conn->_write.pool, stream_id, -errnum);
        h2o_http2_conn_enqueue_write(conn, rst_frame);
    } else {
        enqueue_goaway_and_initiate_close(conn, errnum);
    }
}

static uv_buf_t alloc_inbuf(uv_handle_t *handle, size_t suggested_size)
{
    h2o_http2_conn_t *conn = handle->data;
    return h2o_allocate_input_buffer(&conn->_input, suggested_size);
}

/* handles HEADERS frame or succeeding CONTINUATION frames */
static void handle_incoming_request(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream, const uint8_t *src, size_t len, int is_final)
{
    int allow_psuedo = stream->state == H2O_HTTP2_STREAM_STATE_RECV_PSUEDO_HEADERS;
    if (h2o_hpack_parse_headers(&stream->req, &conn->_input_header_table, &allow_psuedo, src, len) != 0) {
        send_error(conn, stream->stream_id, H2O_HTTP2_ERROR_COMPRESSION);
        return;
    }
    if (! allow_psuedo)
        stream->state = H2O_HTTP2_STREAM_STATE_RECV_HEADERS;

    if (! is_final) {
        /* FIXME request timeout? */
        return;
    }

    /* handle the request */
    conn->_read_expect = expect_default;
    if (kh_size(conn->open_streams) <= HOST_SETTINGS.max_concurrent_streams) {
        stream->state = H2O_HTTP2_STREAM_STATE_SEND_HEADERS;
        conn->max_processed_stream_id = stream->stream_id;
        conn->req_cb(&stream->req);
    } else {
        send_error(conn, stream->stream_id, H2O_HTTP2_ERROR_ENHANCE_YOUR_CALM);
        h2o_http2_stream_close(conn, stream);
    }
}

static ssize_t expect_continuation_of_headers(h2o_http2_conn_t *conn, const uint8_t *src, size_t len)
{
    h2o_http2_frame_t frame;
    ssize_t ret;
    h2o_http2_stream_t *stream;

    if ((ret = h2o_http2_decode_frame(&frame, src, len, &HOST_SETTINGS)) < 0)
        return ret;

    if (! (frame.type == H2O_HTTP2_FRAME_TYPE_CONTINUATION && frame.stream_id == conn->max_open_stream_id))
        return H2O_HTTP2_ERROR_PROTOCOL;

    stream = h2o_http2_conn_get_stream(conn, conn->max_open_stream_id);
    handle_incoming_request(
        conn,
        stream,
        frame.payload,
        frame.length,
        (frame.flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) != 0);

    return ret;
}

static void handle_headers_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    h2o_http2_headers_payload_t payload;
    h2o_http2_stream_t *stream;

    if (frame->stream_id == 0
        || ! (conn->max_open_stream_id < frame->stream_id)
        || h2o_http2_decode_headers_payload(&payload, frame) != 0
        || conn->state == H2O_HTTP2_CONN_STATE_RECVED_GOAWAY) {
        send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
        return;
    }

    conn->_read_expect = expect_continuation_of_headers;

    stream = h2o_http2_stream_open(conn, frame->stream_id, NULL);
    handle_incoming_request(
        conn,
        stream,
        payload.headers,
        payload.headers_len,
        (frame->flags & H2O_HTTP2_FRAME_FLAG_END_HEADERS) != 0);
}

static void resume_send(h2o_http2_conn_t *conn, h2o_http2_stream_t *stream)
{
    if (h2o_http2_window_get_window(&conn->_write.window) <= 0)
        return;

    if (stream != NULL) {
        h2o_http2_stream_send_pending(conn, stream);
    } else {
        /* FIXME priority! */
        h2o_http2_stream_t *stream;
        kh_foreach_value(conn->open_streams, stream, {
            h2o_http2_stream_send_pending(conn, stream);
            if (h2o_http2_window_get_window(&conn->_write.window) <= 0) {
                break;
            }
        });
    }
}

static void handle_settings_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    if (frame->stream_id != 0) {
        send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
        return;
    }

    if ((frame->flags & H2O_HTTP2_FRAME_FLAG_ACK) != 0) {
        if (frame->length != 0) {
            send_error(conn, 0, H2O_HTTP2_ERROR_FRAME_SIZE);
            return;
        }
    } else {
        uint32_t prev_initial_window_size = conn->peer_settings.initial_window_size;
        if (h2o_http2_update_peer_settings(&conn->peer_settings, frame->payload, frame->length) != 0) {
            send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
            return;
        }
        { /* schedule ack */
            uint8_t *header_buf = h2o_mempool_alloc(&conn->_write.pool, H2O_HTTP2_FRAME_HEADER_SIZE);
            h2o_http2_encode_frame_header(header_buf, 0, H2O_HTTP2_FRAME_TYPE_SETTINGS, H2O_HTTP2_FRAME_FLAG_ACK, 0);
            h2o_http2_conn_enqueue_write(conn, uv_buf_init((char*)header_buf, H2O_HTTP2_FRAME_HEADER_SIZE));
        }
        /* apply the change to window size */
        if (prev_initial_window_size != conn->peer_settings.initial_window_size) {
            ssize_t delta = conn->peer_settings.initial_window_size - prev_initial_window_size;
            h2o_http2_stream_t *stream;
            kh_foreach_value(conn->open_streams, stream, {
                h2o_http2_window_update(&stream->window, delta);
            });
            h2o_http2_window_update(&conn->_write.window, delta);
            resume_send(conn, NULL);
        }
    }
}

static void handle_window_update_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    h2o_http2_window_update_payload_t payload;

    if (h2o_http2_decode_window_update_payload(&payload, frame) != 0) {
        send_error(conn, frame->stream_id, H2O_HTTP2_ERROR_PROTOCOL);
        return;
    }

    if (frame->stream_id == 0) {
        h2o_http2_window_update(&conn->_write.window, payload.window_size_increment);
        resume_send(conn, NULL);
    } else if (frame->stream_id <= conn->max_open_stream_id) {
        h2o_http2_stream_t *stream = h2o_http2_conn_get_stream(conn, frame->stream_id);
        if (stream != NULL) {
            h2o_http2_window_update(&stream->window, payload.window_size_increment);
            resume_send(conn, stream);
        }
    } else {
        send_error(conn, 0, H2O_HTTP2_ERROR_FLOW_CONTROL);
    }
}

static void handle_goaway_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    h2o_http2_goaway_payload_t payload;

    assert(conn->state == H2O_HTTP2_CONN_STATE_OPEN);

    if (frame->stream_id != 0 || h2o_http2_decode_goaway_payload(&payload, frame) != 0) {
        send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
        return;
    }

    conn->state = H2O_HTTP2_CONN_STATE_RECVED_GOAWAY;
    gracefully_shutdown_if_possible(conn);
}

static void handle_ping_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    h2o_http2_ping_payload_t payload;
    uv_buf_t pong;

    if (frame->stream_id != 0 || h2o_http2_decode_ping_payload(&payload, frame) != 0) {
        send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
        return;
    }

    pong = h2o_http2_encode_ping_frame(&conn->_write.pool, 1, payload.data);
    h2o_http2_conn_enqueue_write(conn, pong);
}

static void handle_rst_stream_frame(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    h2o_http2_rst_stream_payload_t payload;
    h2o_http2_stream_t *stream;

    if (frame->stream_id == 0
        || conn->max_open_stream_id < frame->stream_id
        || h2o_http2_decode_rst_stream_payload(&payload, frame) != 0) {
        send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
        return;
    }

    stream = h2o_http2_conn_get_stream(conn, frame->stream_id);
    if (stream != NULL) {
        /* reset the stream */
        h2o_http2_stream_reset(conn, stream, -payload.error_code);
    }
    /* TODO log */
}

static void handle_frame_as_protocol_error(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    fprintf(stderr, "received an unexpected frame (type:%d)\n", frame->type);
    send_error(conn, 0, H2O_HTTP2_ERROR_PROTOCOL);
}

static void handle_frame_skip(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame)
{
    fprintf(stderr, "skipping frame (type:%d)\n", frame->type);
}

ssize_t expect_default(h2o_http2_conn_t *conn, const uint8_t *src, size_t len)
{
    h2o_http2_frame_t frame;
    ssize_t ret;
    static void (*FRAME_HANDLERS[])(h2o_http2_conn_t *conn, h2o_http2_frame_t *frame) = {
        handle_frame_skip,              /* DATA */
        handle_headers_frame,
        handle_frame_skip,              /* PRIORITY */
        handle_rst_stream_frame,
        handle_settings_frame,
        handle_frame_as_protocol_error, /* PUSH_PROMISE */
        handle_ping_frame,
        handle_goaway_frame,
        handle_window_update_frame,
        handle_frame_as_protocol_error  /* CONTINUATION */
    };

    if ((ret = h2o_http2_decode_frame(&frame, src, len, &HOST_SETTINGS)) < 0)
        return ret;

    if (frame.type < sizeof(FRAME_HANDLERS) / sizeof(FRAME_HANDLERS[0])) {
        FRAME_HANDLERS[frame.type](conn, &frame);
    } else {
        fprintf(stderr, "skipping frame (type:%d)\n", frame.type);
    }

    return ret;
}

static ssize_t expect_preface(h2o_http2_conn_t *conn, const uint8_t *src, size_t len)
{
    if (len < CONNECTION_PREFACE.len) {
        return H2O_HTTP2_ERROR_INCOMPLETE;
    }
    if (memcmp(src, CONNECTION_PREFACE.base, CONNECTION_PREFACE.len) != 0) {
        return H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY;
    }

    conn->_read_expect = expect_default;
    return CONNECTION_PREFACE.len;
}

static void handle_input(h2o_http2_conn_t *conn)
{
    const uint8_t *src = (uint8_t*)conn->_input->bytes, *src_end = src + conn->_input->size;

    while (conn->state != H2O_HTTP2_CONN_STATE_IS_CLOSING && src != src_end) {
        ssize_t ret = conn->_read_expect(conn, src, src_end - src);
        if (ret < 0) {
            switch (ret) {
            case H2O_HTTP2_ERROR_INCOMPLETE:
                goto Incomplete;
            default:
                /* send error */
                send_error(conn, 0, (int)-ret);
                /* fallthru */
            case H2O_HTTP2_ERROR_PROTOCOL_CLOSE_IMMEDIATELY:
                close_connection(conn);
                break;
            }
            return;
        }
        src += ret;
    }

Incomplete:
    h2o_consume_input_buffer(&conn->_input, conn->state != H2O_HTTP2_CONN_STATE_IS_CLOSING ? (char*)src - conn->_input->bytes : conn->_input->size);
}

static void on_read(uv_stream_t *stream, ssize_t nread, uv_buf_t _buf)
{
    h2o_http2_conn_t *conn = stream->data;

    if (nread == -1) {
        /* FIXME should we support shutdown? */
        uv_read_stop((uv_stream_t*)conn->stream);
        close_connection(conn);
    } else {
        conn->_input->size += nread;
        handle_input(conn);
    }
}

static void on_upgrade_complete(void *_conn, uv_stream_t *stream, h2o_input_buffer_t *buffered_input, size_t reqsize)
{
    h2o_http2_conn_t *conn = _conn;

    if (stream == NULL) {
        close_connection(conn);
        return;
    }

    conn->stream = stream;
    stream->data = conn;
    conn->_http1_req_input = buffered_input;

    /* setup inbound */
    uv_read_start(conn->stream, alloc_inbuf, on_read);

    /* handle the request */
    conn->max_processed_stream_id = 1;
    conn->req_cb(&h2o_http2_conn_get_stream(conn, 1)->req);

    if (conn->_http1_req_input->size != reqsize) {
        /* FIXME copy the remaining data to conn->_input and call handle_input */
        assert(0);
    }
}

void h2o_http2_conn_enqueue_write(h2o_http2_conn_t *conn, uv_buf_t buf)
{
    /* activate the timeout if not yet being done */
    if (conn->_write.bufs.size == 0) {
        h2o_timeout_link_entry(&conn->ctx->zero_timeout, &conn->_write.timeout_entry);
    }
    /* push the buf */
    h2o_vector_reserve(&conn->_write.pool, (h2o_vector_t*)&conn->_write.bufs, sizeof(uv_buf_t), conn->_write.bufs.size + 1);
    conn->_write.bufs.entries[conn->_write.bufs.size++] = buf;
}

static void on_write_complete(uv_write_t *wreq, int status)
{
    h2o_http2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _write.wreq, wreq);
    h2o_http2_stream_t *flushed_streams = conn->_write.flushed_streams;

    /* reset the memory pool */
    h2o_mempool_clear(&conn->_write.pool);
    memset(&conn->_write.bufs, 0, sizeof(conn->_write.bufs));
    conn->_write.flushed_streams = NULL;

    /* update the streams */
    if (flushed_streams != NULL) {
        while (1) {
            h2o_http2_stream_t *next = flushed_streams->_send_queue._next_flushed;
            flushed_streams->_send_queue._next_flushed = NULL;
            if (conn->state != H2O_HTTP2_CONN_STATE_RECVED_GOAWAY)
                h2o_http2_stream_proceed(conn, flushed_streams, status);
            if (flushed_streams == next)
                break;
            flushed_streams = next;
        }
    }

    /* close the connection if approprate */
    if (status != 0) {
        conn->state = H2O_HTTP2_CONN_STATE_IS_CLOSING;
    }
    switch (conn->state) {
    case H2O_HTTP2_CONN_STATE_IS_CLOSING:
        close_connection_now(conn);
        break;
    case H2O_HTTP2_CONN_STATE_RECVED_GOAWAY:
        gracefully_shutdown_if_possible(conn);
        break;
    default:
        break;
    }
}

static void emit_writereq(h2o_timeout_entry_t *entry)
{
    h2o_http2_conn_t *conn = H2O_STRUCT_FROM_MEMBER(h2o_http2_conn_t, _write.timeout_entry, entry);

    assert(conn->_write.bufs.size != 0);
    uv_write(&conn->_write.wreq, conn->stream, conn->_write.bufs.entries, (int)conn->_write.bufs.size, on_write_complete);
}

void h2o_http2_close_and_free(h2o_http2_conn_t *conn)
{
    if (conn->stream != NULL)
        uv_close((uv_handle_t*)conn->stream, (uv_close_cb)free);
    free(conn);
}

int h2o_http2_handle_upgrade(h2o_req_t *req, h2o_http2_conn_t *http2conn)
{
    ssize_t connection_index, settings_index;
    uv_buf_t settings_decoded;

    assert(req->version < 0x200); /* from HTTP/1.x */

    /* init the connection */
    http2conn->stream = NULL; /* not set until upgrade is complete */
    http2conn->ctx = req->ctx;
    http2conn->peer_settings = H2O_HTTP2_SETTINGS_DEFAULT;
    http2conn->open_streams = kh_init(h2o_http2_stream_t);
    http2conn->max_open_stream_id = 0;
    http2conn->max_processed_stream_id = 0;
    http2conn->state = H2O_HTTP2_CONN_STATE_OPEN;
    http2conn->_read_expect = expect_preface;
    http2conn->_input = NULL;
    http2conn->_http1_req_input = NULL;
    memset(&http2conn->_input_header_table, 0, sizeof(http2conn->_input_header_table));
    http2conn->_input_header_table.hpack_capacity = H2O_HTTP2_SETTINGS_DEFAULT.header_table_size;
    h2o_mempool_init(&http2conn->_write.pool);
    memset(&http2conn->_write.wreq, 0, sizeof(http2conn->_write.wreq));
    memset(&http2conn->_write.bufs, 0, sizeof(http2conn->_write.bufs));
    http2conn->_write.flushed_streams = NULL;
    memset(&http2conn->_write.timeout_entry, 0, sizeof(http2conn->_write.timeout_entry));
    http2conn->_write.timeout_entry.cb = emit_writereq;
    h2o_http2_window_init(&http2conn->_write.window, &http2conn->peer_settings);

    /* check that "HTTP2-Settings" is declared in the connection header */
    connection_index = h2o_find_header(&req->headers, H2O_TOKEN_CONNECTION, -1);
    assert(connection_index != -1);
    if (! h2o_contains_token(req->headers.entries[connection_index].value.base, req->headers.entries[connection_index].value.len, H2O_STRLIT("http2-settings"))) {
        return -1;
    }

    /* decode the settings */
    if ((settings_index = h2o_find_header(&req->headers, H2O_TOKEN_HTTP2_SETTINGS, -1)) == -1) {
        return -1;
    }
    if ((settings_decoded = h2o_decode_base64url(&req->pool, req->headers.entries[settings_index].value.base, req->headers.entries[settings_index].value.len)).base == NULL) {
        return -1;
    }
    if (h2o_http2_update_peer_settings(&http2conn->peer_settings, (uint8_t*)settings_decoded.base, settings_decoded.len) != 0) {
        return -1;
    }

    /* open the stream, now that the function is guaranteed to succeed */
    h2o_http2_stream_open(http2conn, 1, req);

    /* send response */
    req->res.status = 101;
    req->res.reason = "Switching Protocols";
    h2o_add_header(&req->pool, &req->res.headers, H2O_TOKEN_UPGRADE, H2O_STRLIT("h2c"));
    h2o_http1_upgrade(req->conn, (uv_buf_t*)&HOST_SETTINGS_BIN, 1, on_upgrade_complete, http2conn);

    return 0;
}
