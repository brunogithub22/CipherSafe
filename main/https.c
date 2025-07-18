#include "function.c"


static const mime_map_t mime_table[] = {
    { ".htm",  "text/html" },
    { ".html", "text/html" },
    { ".js",   "application/javascript" },
    { ".css",  "text/css" },
    { ".png",  "image/png" },
    { ".ico",  "image/x-icon" },
    { ".svg",  "image/svg+xml" },
    { ".json", "application/json" },
};

static esp_err_t set_content_type_from_file(httpd_req_t *req, const char *filepath) {
    const char *mime = "application/octet-stream";
    const char *dot  = strrchr(filepath, '.');
    if (dot) {
        for (size_t i = 0; i < ARRAY_SIZE(mime_table); ++i) {
            if (strcasecmp(dot, mime_table[i].ext) == 0) {
                mime = mime_table[i].mime;
                break;
            }
        }
    }
    return httpd_resp_set_type(req, mime);
}

static esp_err_t serve_static_stream(httpd_req_t *req, const char *fullpath)
{
    int fd = open(fullpath, O_RDONLY);
    if (fd < 0) {
        ESP_LOGW(TAG, "File not found: %s", fullpath);
        return ESP_FAIL;
    }

    set_content_type_from_file(req, fullpath);

    static uint8_t chunk[CHUNK_BUF_SIZE];
    ssize_t r;
    while ((r = read(fd, chunk, sizeof(chunk))) > 0) {
        uint8_t *ptr     = chunk;
        ssize_t to_send  = r;
        while (to_send > 0) {
            esp_err_t w = httpd_resp_send_chunk(req, (const char*)ptr, to_send);
            if (w == ESP_TLS_ERR_SSL_WANT_WRITE || w == ESP_TLS_ERR_SSL_WANT_READ) {
                // MbedTLS in “would-block”: riprova
                vTaskDelay(pdMS_TO_TICKS(1));
                continue;
            }
            if (w != ESP_OK) {
                ESP_LOGE(TAG, "Chunk send failed: %d", w);
                close(fd);
                return ESP_FAIL;
            }
            // tutto il chunk è andato
            to_send = 0;
        }
        // lascio respirare la task di rete
        vTaskDelay(pdMS_TO_TICKS(1));
    }

    close(fd);
    if (r < 0) {
        ESP_LOGE(TAG, "Error reading file: %s", fullpath);
        return ESP_FAIL;
    }

    // chiudo il chunked-stream (MANDARLO UNA SOLA VOLTA)
    if (httpd_resp_send_chunk(req, NULL, 0) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to send final chunk");
        return ESP_FAIL;
    }

    return ESP_OK;
}



//———————————————————————————————————————————————————
// POST body reader and sign-in/up handlers — unchanged
static char * read_request_body(httpd_req_t *req, size_t *out_len) {
    size_t len = req->content_len;
    if (len == 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Empty body");
        return NULL;
    }
    char *buf = malloc(len + 1);
    if (!buf) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Out of memory");
        return NULL;
    }
    size_t read = 0;
    while (read < len) {
        int ret = httpd_req_recv(req, buf + read, len - read);
        if (ret <= 0) {
            free(buf);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Receive error");
            return NULL;
        }
        read += ret;
    }
    buf[len] = '\0';
    *out_len = len;
    return buf;
}



static esp_err_t get_handler(httpd_req_t *req){
    const char *uri = req->uri;
    char filepath[FILE_PATH_MAX];
    rest_server_context_t *ctx = (rest_server_context_t *)req->user_ctx;
    
    if(strcmp(uri,"/CIPHER~1/FILE~1.JSO")==0){
        strlcpy(filepath, ctx->base_path, sizeof(filepath));
        strlcat(filepath, uri, sizeof(filepath));
        ESP_LOGI(TAG,"GET JSON %s -> %s", uri, filepath);
        size_t len; char *b=NULL;
        bool ok = read_file(filepath,&b,&len);
        if(!ok){
            return httpd_resp_send_err(req,HTTPD_404_NOT_FOUND,"File not found");
        }
        httpd_resp_set_type(req,"application/json");
        httpd_resp_send(req,b,len);
        free(b);
        return ESP_OK;
    } else{
        // static under /HTML
        strlcpy(filepath, ctx->base_path, sizeof(filepath));
        strlcat(filepath, "/HTML", sizeof(filepath));
        if(uri[strlen(uri)-1]=='/')
            strlcat(filepath, "/INDEX~1.HTM", sizeof(filepath));
        else
            strlcat(filepath, uri, sizeof(filepath));
        ESP_LOGI(TAG,"GET static %s -> %s", uri, filepath);
        esp_err_t err = serve_static_stream(req, filepath);
        if(err==ESP_FAIL){
            return httpd_resp_send_err(req,HTTPD_404_NOT_FOUND,"File not found");
        }
        return ESP_OK;
    }
}


static esp_err_t email_handler(httpd_req_t *req) {
    size_t body_len;
    char *body = read_request_body(req, &body_len);
    if (!body){
          
        return ESP_FAIL;
    }
    return email_send(body, req);
}


static esp_err_t sign_up_handler(httpd_req_t *req) {
    size_t body_len;
    char *body = read_request_body(req, &body_len);
    if (!body){
          
        return ESP_FAIL;
    }
    return sign_up(body, req);
}

static esp_err_t sign_in_handler(httpd_req_t *req) {
    size_t body_len;
    char *body = read_request_body(req, &body_len);
    if (!body){
          
        return ESP_FAIL;
    }
    return sign_in(body, req);
}

static esp_err_t new_archive_handler(httpd_req_t *req) {
    size_t body_len;
    char *body = read_request_body(req, &body_len);
    if (!body){
          
        return ESP_FAIL;
    }
    return new_archive(body, req);
}

static esp_err_t load_file_handler(httpd_req_t *req) {
    size_t body_len;
    char *body = read_request_body(req, &body_len);
    if (!body){
          
        return ESP_FAIL;
    }
    return load_file(body, req);
}

static esp_err_t delete_archive_handler(httpd_req_t *req) {
    size_t body_len;
    char *body = read_request_body(req, &body_len);
    if (!body){
          
        return ESP_FAIL;
    }
    return delete_archive(body, req);
}

static esp_err_t delete_account_handler(httpd_req_t *req) {
    size_t body_len;
    char *body = read_request_body(req, &body_len);
    if (!body){
          
        return ESP_FAIL;
    }
    return delete_account(body, req);
}


esp_err_t send_code_handler(httpd_req_t *req){
    size_t body_len;
    char *body = read_request_body(req, &body_len);
    if (!body){
          
        return ESP_FAIL;
    }
    return send_code(body, req);
}

esp_err_t change_password_handler(httpd_req_t *req){
    size_t body_len;
    char *body = read_request_body(req, &body_len);
    if (!body){
          
        return ESP_FAIL;
    }
    return change_password(body, req);
}


static httpd_handle_t start_webserver(rest_server_context_t *rest_context) {
    // load cert/key
    char *cert, *key;
    size_t cert_len, key_len;
    if (read_file(MOUNT_POINT "/CERT/SERVER.CRT", &cert, &cert_len) != true ||
        read_file(MOUNT_POINT "/CERT/SERVER.KEY", &key, &key_len) != true) {
        ESP_LOGE(TAG, "Failed to load cert/key");
        return NULL;
    }

    // configure HTTPS server
    httpd_ssl_config_t config = HTTPD_SSL_CONFIG_DEFAULT();
    config.httpd.uri_match_fn = httpd_uri_match_wildcard;
    config.httpd.enable_so_linger     = true;
    config.httpd.linger_timeout       = 10;   // aspetta fino a 10s per i dati in coda
    config.httpd.keep_alive_enable    = true;
    config.httpd.keep_alive_idle      = 30;   // attiva keep-alive dopo 30s di inattività
    config.httpd.keep_alive_interval  = 5;    // invia un ping ogni 5s
    config.httpd.keep_alive_count     = 3;    // per 3 volte
    config.httpd.max_open_sockets   = 7;  // di default: 5
    config.httpd.max_uri_handlers   = 16;  // il numero di URI che registri
    config.httpd.server_port = 443;
    config.servercert     = (const unsigned char*)cert;
    config.servercert_len = cert_len+1;
    config.prvtkey_pem    = (const unsigned char*)key;
    config.prvtkey_len    = key_len+1;

    httpd_handle_t server = NULL;
    if (httpd_ssl_start(&server, &config) != ESP_OK ) {
        ESP_LOGE(TAG, "HTTPS start failed");
        return NULL;
    }
    // register URIs
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/sign_up", .method = HTTP_POST, .handler = sign_up_handler, .user_ctx = rest_context
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/sign_in", .method = HTTP_POST, .handler = sign_in_handler, .user_ctx = rest_context
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/new_archive", .method = HTTP_POST, .handler = new_archive_handler, .user_ctx = rest_context
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/load_file", .method = HTTP_POST, .handler = load_file_handler, .user_ctx = rest_context
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/upload_chunk", .method = HTTP_POST, .handler = upload_chunk_handler, .user_ctx = rest_context
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/upload_start", .method = HTTP_POST, .handler = upload_start_handler, .user_ctx = rest_context
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/upload_finalize", .method = HTTP_POST, .handler = upload_finalize_handler, .user_ctx = rest_context
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/download", .method = HTTP_POST, .handler = download_handler, .user_ctx = rest_context
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/delete", .method = HTTP_POST, .handler = delete_handler, .user_ctx = rest_context
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/delete_archive", .method = HTTP_POST, .handler = delete_archive_handler, .user_ctx = rest_context
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/delete_account", .method = HTTP_POST, .handler = delete_account_handler, .user_ctx = rest_context
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/email_verify", .method = HTTP_POST, .handler = email_handler, .user_ctx = rest_context
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/send_code", .method = HTTP_POST, .handler = send_code_handler, .user_ctx = rest_context
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/change_password", .method = HTTP_POST, .handler = change_password_handler, .user_ctx = rest_context
    });
    httpd_register_uri_handler(server, &(httpd_uri_t){
        .uri = "/*", .method = HTTP_GET, .handler = get_handler, .user_ctx = rest_context
    });
    
    ESP_LOGI(TAG, "HTTPS server running");
    return server;
}

void web_server(void){
    static rest_server_context_t rest_context;
    strlcpy(rest_context.base_path, "/sdcard", sizeof(rest_context.base_path));
    httpd_handle_t server = start_webserver(&rest_context);
    if (server == NULL) {
        printf( "\nFailed to start web server\n");          
    }
}