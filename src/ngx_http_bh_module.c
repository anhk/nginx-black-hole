
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#define DEBUG  NGX_LOG_DEBUG
#define INFO  NGX_LOG_INFO
#define ERR  NGX_LOG_ERR

#define log(level, fmt, ...) do {                           \
    ngx_log_error(level, ngx_cycle->log, 0, "[%s:%d] " fmt, \
            __FUNCTION__, __LINE__, ##__VA_ARGS__);         \
} while (0)


typedef struct _ngx_http_bh_loc_conf_s {
    ngx_flag_t enable;
    ngx_int_t code;
    ngx_str_t response;
    ngx_str_t ct;           /** Content-Type **/
} ngx_http_bh_loc_conf_t;

extern ngx_module_t ngx_http_bh_module;


static ngx_int_t do_send_header(ngx_http_request_t *r)
{
    ngx_http_bh_loc_conf_t *blcf;
    ngx_int_t rc;
    ngx_buf_t *b;
    ngx_chain_t out;

    if ((blcf = ngx_http_get_module_loc_conf(r, ngx_http_bh_module)) == NULL) {
        return NGX_DECLINED;
    }

    if (blcf->code == NGX_CONF_UNSET) {
        r->headers_out.status = NGX_HTTP_OK;
    } else {
        r->headers_out.status = blcf->code;
    }
    r->headers_out.content_length_n = blcf->response.len;
    r->keepalive = 1;

    if (blcf->response.len == 0) {
        r->header_only = 1;
        return ngx_http_send_header(r);
    }

    r->headers_out.content_type = blcf->ct;

    if ((rc = ngx_http_send_header(r)) != NGX_OK) {
        return rc;
    }

    if ((b = ngx_create_temp_buf(r->pool, blcf->response.len)) == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(b->pos, blcf->response.data, blcf->response.len);
    b->last = b->pos + blcf->response.len;
    b->last_buf = 1;

    out.buf = b;
    out.next = NULL;
    return ngx_http_output_filter(r, &out);
}


static ngx_int_t ngx_http_test_expect(ngx_http_request_t *r)
{
    ngx_int_t   n;
    ngx_str_t  *expect;

    if (r->expect_tested
            || r->headers_in.expect == NULL
            || r->http_version < NGX_HTTP_VERSION_11
#if (NGX_HTTP_V2)
            || r->stream != NULL
#endif
       )
    {
        return NGX_OK;
    }

    r->expect_tested = 1;

    expect = &r->headers_in.expect->value;

    if (expect->len != sizeof("100-continue") - 1
            || ngx_strncasecmp(expect->data, (u_char *) "100-continue",
                sizeof("100-continue") - 1)
            != 0)
    {
        return NGX_OK;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
            "send 100 Continue");

    n = r->connection->send(r->connection,
            (u_char *) "HTTP/1.1 100 Continue" CRLF CRLF,
            sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1);

    if (n == sizeof("HTTP/1.1 100 Continue" CRLF CRLF) - 1) {
        return NGX_OK;
    }

    /* we assume that such small packet should be send successfully */

    r->connection->error = 1;

    return NGX_ERROR;
}

static ngx_int_t discard_request_body_filter(ngx_http_request_t *r, ngx_buf_t *b)
{
    size_t size;
    ngx_int_t rc;
    ngx_http_request_body_t *rb;

    if (r->headers_in.chunked) {
        if ((rb = r->request_body) == NULL) {
            if ((rb = ngx_pcalloc(r->pool, sizeof(ngx_http_request_body_t))) == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            if ((rb->chunked = ngx_pcalloc(r->pool, sizeof(ngx_http_chunked_t))) == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }
            r->request_body = rb;
        }

        for (;;) {
            rc = ngx_http_parse_chunked(r, b, rb->chunked);

            if (rc == NGX_OK) {
                size = b->last - b->pos;
                if ((off_t)size > rb->chunked->size) {
                    b->pos += (size_t)rb->chunked->size;
                    rb->chunked->size = 0;
                } else {
                    rb->chunked->size -= size;
                    b->pos = b->last;
                }
                continue;
            } else if (rc == NGX_DONE) {
                r->headers_in.content_length_n = 0;
                break;
            } else if (rc == NGX_AGAIN) {
                r->headers_in.content_length_n = rb->chunked->length;
                break;
            }

            return NGX_HTTP_BAD_REQUEST;
        }
    } else {
        size = b->last - b->pos;

        if ((off_t)size > r->headers_in.content_length_n) {
            b->pos += (size_t) r->headers_in.content_length_n;
            r->headers_in.content_length_n = 0;
        } else {
            b->pos = b->last;
            r->headers_in.content_length_n -= size;
        }
    }
    return NGX_OK;
}

static ngx_int_t do_read_discarded_request_body(ngx_http_request_t *r)
{
    ngx_buf_t b;
    size_t size;
    ssize_t n;
    ngx_int_t rc;

    u_char buffer[NGX_HTTP_DISCARD_BUFFER_SIZE];

    ngx_memzero(&b, sizeof(ngx_buf_t));

    b.temporary = 1;

    for (;;) {
        if (r->headers_in.content_length_n == 0) {
            r->read_event_handler = ngx_http_block_reading;
            return NGX_OK;
        }

        if (!r->connection->read->ready) {
            return NGX_AGAIN;
        }

        size = (size_t) ngx_min(r->headers_in.content_length_n,
                NGX_HTTP_DISCARD_BUFFER_SIZE);

        n = r->connection->recv(r->connection, buffer, size);

        if (n == NGX_ERROR) {
            r->connection->error = 1;
            return NGX_OK;
        }

        if (n == NGX_AGAIN) {
            return NGX_AGAIN;
        }

        if (n == 0) {
            return NGX_OK;
        }

        b.pos = buffer;
        b.last = buffer + n;

        if ((rc = discard_request_body_filter(r, &b)) != NGX_OK) {
            return rc;
        }
    }

    return NGX_OK;
}

static void do_discarded_request_body_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_msec_t timer;
    ngx_connection_t *c = r->connection;
    ngx_event_t *rev = c->read;
    ngx_http_core_loc_conf_t *clcf;

    if (rev->timedout) {
        c->timedout = 1;
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    if (r->lingering_time) {
        timer = (ngx_msec_t)r->lingering_time - (ngx_msec_t)ngx_time();
        if ((ngx_msec_int_t) timer <= 0) {
            r->lingering_close = 0;
            ngx_http_finalize_request(r, NGX_ERROR);
            return;
        }
    } else {
        timer = 0;
    }

    rc = do_read_discarded_request_body(r);

    if (rc == NGX_OK) {
        r->lingering_close = 0;
        do_send_header(r);
        ngx_http_finalize_request(r, NGX_DONE);
        return;
    }

    /** rc == NGX_AGAIN **/
    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        c->error = 1;
        ngx_http_finalize_request(r, NGX_ERROR);
        return;
    }

    if (timer) {
        clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
        timer *= 1000;

        if (timer > clcf->lingering_timeout) {
            timer = clcf->lingering_timeout;
        }
        ngx_add_timer(rev, timer);
    }
}

static ngx_int_t do_discard_body(ngx_http_request_t *r)
{
    ngx_int_t rc;
    size_t preread;
    ngx_event_t *rev;

    if (r != r->main) {
        return NGX_OK;
    }

#if (NGX_HTTP_V2)
    if (r->stream) {
        r->stream->skip_data = 1;
        return NGX_OK;
    }
#endif

    if (ngx_http_test_expect(r) != NGX_OK) {
        log(ERR, "ngx_http_test_expect failed.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rev = r->connection->read;
    if (rev->timer_set) {
        ngx_del_timer(rev);
    }

    if (r->headers_in.content_length_n <= 0 && !r->headers_in.chunked) {
        log(ERR, "r->headers_in.content_length_n <= 0 && !r->headers_in.chunked");
        return do_send_header(r);
    }

    preread = r->header_in->last - r->header_in->pos;
    if (preread || r->headers_in.chunked) {
        if ((rc = discard_request_body_filter(r, r->header_in)) != NGX_OK) {
            return rc;
        }
        if (r->headers_in.content_length_n == 0) {
            return do_send_header(r);
        }
    }

    if ((rc = do_read_discarded_request_body(r)) == NGX_OK) {
        r->lingering_close = 0;
        return do_send_header(r);
    }

    if (rc >= NGX_HTTP_SPECIAL_RESPONSE) {
        log(ERR, "rc >= NGX_HTTP_SPECIAL_RESPONSE: %d", rc);
        return rc;
    }

    /** rc == NGX_AGAIN **/
    r->read_event_handler = do_discarded_request_body_handler;

    if (ngx_handle_read_event(rev, 0) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    r->count ++;
    return NGX_DONE;
}

static ngx_int_t ngx_http_bh_content_handler(ngx_http_request_t *r)
{
    ngx_http_bh_loc_conf_t *blcf;

    if ((blcf = ngx_http_get_module_loc_conf(r, ngx_http_bh_module)) == NULL) {
        return NGX_DECLINED;
    }

    if (blcf->enable != 1) {
        return NGX_DECLINED;
    }

    return do_discard_body(r);
}

static ngx_int_t ngx_http_bh_init_post_config(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t *cmcf;
    ngx_http_handler_pt *h;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    if ((h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers)) == NULL) {
        return NGX_ERROR;
    }
    *h = ngx_http_bh_content_handler;
    return NGX_OK;
}

static void *ngx_http_bh_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_bh_loc_conf_t *blcf;

    if ((blcf = ngx_palloc(cf->pool, sizeof(ngx_http_bh_loc_conf_t))) == NULL) {
        return NULL;
    }
    blcf->enable = NGX_CONF_UNSET;
    blcf->code = NGX_CONF_UNSET;
    blcf->response.data = NULL;
    blcf->response.len = 0;
    return blcf;
}

static ngx_command_t ngx_http_bh_commands[] = {

    { ngx_string("black-hole"),
        NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_bh_loc_conf_t, enable),
        NULL },

    { ngx_string("black-hole-code"),
        NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_num_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_bh_loc_conf_t, code),
        NULL },

    { ngx_string("black-hole-response"),
        NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_bh_loc_conf_t, response),
        NULL },

    { ngx_string("black-hole-content-type"),
        NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_bh_loc_conf_t, ct),
        NULL },

    ngx_null_command
};

static ngx_http_module_t ngx_http_bh_module_ctx = {
    NULL,                           /* preconfiguration */
    ngx_http_bh_init_post_config,   /* postconfiguration */

    NULL,                           /* create main configuration */
    NULL,                           /* init main configuration */

    NULL,                           /* create server configuration */
    NULL,                           /* merge server configuration */

    ngx_http_bh_create_loc_conf,    /* create location configuration */
    NULL                            /* merge location configuration */
};

ngx_module_t ngx_http_bh_module = {
    NGX_MODULE_V1,
    &ngx_http_bh_module_ctx,        /* module context */
    ngx_http_bh_commands,           /* module directives */
    NGX_HTTP_MODULE,                /* module type */
    NULL,                           /* init master */
    NULL,                           /* init module */
    NULL,                           /* init process */
    NULL,                           /* init thread */
    NULL,                           /* exit thread */
    NULL,                           /* exit process */
    NULL,                           /* exit master */
    NGX_MODULE_V1_PADDING
};
