
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct _ngx_http_bh_loc_conf_s {
    ngx_flag_t enable;
} ngx_http_bh_loc_conf_t;

extern ngx_module_t ngx_http_bh_module;

static ngx_int_t ngx_http_bh_content_handler(ngx_http_request_t *r)
{
    ngx_int_t rc;
    ngx_http_bh_loc_conf_t *blcf;

    if ((blcf = ngx_http_get_module_loc_conf(r, ngx_http_bh_module)) == NULL) {
        return NGX_DECLINED;
    }

    if (blcf->enable != 1) {
        return NGX_DECLINED;
    }

    if ((rc = ngx_http_discard_request_body(r)) != NGX_OK) {
        return rc;
    }
    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = 0;
    r->header_only = 1;
    if ((rc = ngx_http_send_header(r)) != NGX_OK) {
        return rc;
    } else {
        r->keepalive = 1;
    }
    return NGX_OK;
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
    return blcf;
}

static ngx_command_t ngx_http_bh_commands[] = {

    { ngx_string("black-hole"),
        NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
        ngx_conf_set_flag_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_bh_loc_conf_t, enable),
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
