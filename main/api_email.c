#include "wifi.c"

#define API_KEY  "xsmtpsib-2b249c3f97635599ac6a98a6f0eff47ffc688e74afc3cb7e9c42dd702705951d-4zL1SwV2Jm68DN5f"   // metti qui la tua API key

// -----------------------------------------------------------------------------
// 2) HTTPS request che usa il PEM passato come trust‑anchor
// -----------------------------------------------------------------------------
static esp_err_t https_request_with_pem(
        const char *url,
        esp_http_client_method_t method,
        const char *body,
        const char *pem,      // buffer PEM caricato
        char **out_response)
{
    esp_http_client_config_t cfg = {
        .url                         = url,
        .method                      = method,
        .timeout_ms                  = 5000,
        .cert_pem                    = pem,
        .skip_cert_common_name_check = false,
    };

    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) {
        ESP_LOGE(TAG, "http_client_init failed");
        return ESP_FAIL;
    }

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "api-key", API_KEY);
    if (body) {
        esp_http_client_set_post_field(client, body, strlen(body));
    }

    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK && out_response) {
        int len = esp_http_client_get_content_length(client);
        if (len > 0) {
            *out_response = malloc(len + 1);
            if (*out_response) {
                int r = esp_http_client_read_response(client, *out_response, len);
                if (r > 0) {
                    (*out_response)[r] = '\0';
                } else {
                    (*out_response)[0] = '\0';
                }
            } else {
                ESP_LOGE(TAG, "malloc failed for response buffer");
            }
        }
    } else if (err != ESP_OK) {
        ESP_LOGE(TAG, "HTTP request failed: %s", esp_err_to_name(err));
    }

    esp_http_client_cleanup(client);
    return err;
}

// -----------------------------------------------------------------------------
// 3) URL‑encode RFC3986 per query‑string
// -----------------------------------------------------------------------------
static char* url_encode(const char *s) {
    const char *hex = "0123456789ABCDEF";
    size_t len = strlen(s);
    char *enc = malloc(len * 3 + 1);
    if (!enc) return NULL;

    char *p = enc;
    for (size_t i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (isalnum(c) || c=='-'||c=='.'||c=='_'||c=='~') {
            *p++ = c;
        } else {
            *p++ = '%';
            *p++ = hex[c >> 4];
            *p++ = hex[c & 0x0F];
        }
    }
    *p = '\0';
    return enc;
}

// -----------------------------------------------------------------------------
// 4) brevo_validate_email: carica la CA, costruisce URL, chiama HTTPS
// -----------------------------------------------------------------------------
bool brevo_validate_email(const char *email, char **out_json)
{
    if (!email) {
        ESP_LOGE(TAG, "email is NULL");
        return false;
    }

    // 4.1) percent‑encode email
    char *enc = url_encode(email);
    if (!enc) {
        ESP_LOGE(TAG, "url_encode failed");
        return false;
    }

    // 4.2) build URL
    const char *base = "https://api.brevo.com/v3/email/validate?email=";
    size_t url_len = strlen(base) + strlen(enc) + 1;
    char *url = malloc(url_len);
    if (!url) {
        ESP_LOGE(TAG, "malloc failed");
        free(enc);
        return false;
    }
    int n = snprintf(url, url_len, "%s%s", base, enc);
    free(enc);
    if (n < 0 || (size_t)n >= url_len) {
        ESP_LOGE(TAG, "URL invalid or too long (%d)", n);
        free(url);
        return false;
    }
    ESP_LOGI(TAG, "Built URL: %s", url);

    char *pem = NULL;
    size_t pem_len;
    if(file_exsist(MOUNT_POINT"/CERT/ISRGRO~1.PEM")){
        read_file(MOUNT_POINT"/CERT/ISRGRO~1.PEM",&pem,&pem_len);
        if (!pem) {
            ESP_LOGE(TAG, "Failed to load CA PEM");
            return false;
        }
        // 4.4) effettua la richiesta HTTPS
        bool ok = (https_request_with_pem(url, HTTP_METHOD_GET, NULL, pem, out_json) == ESP_OK);

        free(pem);
        free(url);
        return ok;
        
    }else{
        return false;
    }
}

// -----------------------------------------------------------------------------
// 5) brevo_send_email: idem con POST
// -----------------------------------------------------------------------------
bool brevo_send_email(const char *from, const char *to,
                      const char *subject, const char *content,
                      char **out_json)
{
    // 5.1) build JSON body dinamico
    size_t body_len = 100 + strlen(from) + strlen(to) + strlen(subject) + strlen(content);
    char *body = malloc(body_len);
    if (!body) {
        ESP_LOGE(TAG, "malloc failed for email body");
        return false;
    }
    int n = snprintf(body, body_len,
        "{"
          "\"sender\": { \"email\": \"%s\" },"
          "\"to\": [{ \"email\": \"%s\" }],"
          "\"subject\": \"%s\","
          "\"textContent\": \"%s\""
        "}", from, to, subject, content);
    if (n < 0 || (size_t)n >= body_len) {
        ESP_LOGE(TAG, "Email body too long (%d)", n);
        free(body);
        return false;
    }

    char *pem = NULL;
    size_t pem_len;
    if(file_exsist(MOUNT_POINT"/CERT/ISRGRO~1.PEM")){
        read_file(MOUNT_POINT"/CERT/ISRGRO~1.PEM",&pem,&pem_len);
        if (!pem) {
            ESP_LOGE(TAG, "Failed to load CA PEM");
            free(body);
            return false;
        }

        // 5.3) HTTPS POST
        bool ok = (https_request_with_pem("https://api.brevo.com/v3/smtp/email",HTTP_METHOD_POST, body, pem, out_json)== ESP_OK);

        free(pem);
        free(body);
        return ok;
    }else{
        return false;
    }
    
}

