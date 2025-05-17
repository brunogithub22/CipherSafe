#include "sd_card.c"

#define MAX_SSID_LEN_CHAR  32
#define MAX_PWD_LEN_CHAR   64

static char ip_address[16];
static EventGroupHandle_t wifi_event_group;
enum {
    WIFI_CONNECTED_BIT = BIT0,
    WIFI_STARTED_BIT   = BIT1
};
static int retry_count = 0;

static unsigned char SSID[MAX_SSID_LEN_CHAR] = {0};
static unsigned char PWD [MAX_PWD_LEN_CHAR]   = {0};

typedef struct {
    char ssid[MAX_SSID_LEN_CHAR];
    char pwd [MAX_PWD_LEN_CHAR];
} wifi_t;

/* ----------------------------------------------------------------------------
   Legge le credenziali Wi‑Fi da JSON su SD (SD già montata in app_main)
   ---------------------------------------------------------------------------- */
static wifi_t* file_wifi(int *out_count) {
    const char *filename = MOUNT_POINT"/CIPHER~1/WIFI~1.JSO";
    ESP_LOGI(TAG, "Reading Wi‑Fi creds from %s", filename);

    FILE *f = fopen(filename, "r");
    if (!f) {
        ESP_LOGE(TAG, "Failed to open %s", filename);
        return NULL;
    }
    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    char *data = malloc(len + 1);
    if (!data) {
        ESP_LOGE(TAG, "Out of memory for JSON buffer");
        fclose(f);
        return NULL;
    }
    fread(data, 1, len, f);
    data[len] = '\0';
    fclose(f);

    cJSON *root = cJSON_Parse(data);
    free(data);
    if (!root) {
        ESP_LOGE(TAG, "JSON parse error: %s", cJSON_GetErrorPtr());
        return NULL;
    }

    cJSON *arr = cJSON_GetObjectItem(root, "wifi");
    if (!cJSON_IsArray(arr)) {
        ESP_LOGE(TAG, "'wifi' not an array");
        cJSON_Delete(root);
        return NULL;
    }

    int count = cJSON_GetArraySize(arr);
    ESP_LOGI(TAG, "Found %d network entries in JSON", count);
    wifi_t *list = calloc(count, sizeof(wifi_t));
    if (!list) {
        ESP_LOGE(TAG, "calloc failed");
        cJSON_Delete(root);
        return NULL;
    }

    for (int i = 0; i < count; ++i) {
        cJSON *item = cJSON_GetArrayItem(arr, i);
        cJSON *js   = cJSON_GetObjectItem(item, "SSID");
        cJSON *jp   = cJSON_GetObjectItem(item, "pwd");
        if (cJSON_IsString(js) && cJSON_IsString(jp)) {
            strncpy(list[i].ssid, js->valuestring, MAX_SSID_LEN_CHAR - 1);
            strncpy(list[i].pwd,   jp->valuestring, MAX_PWD_LEN_CHAR - 1);
            list[i].ssid[MAX_SSID_LEN_CHAR-1] = '\0';
            list[i].pwd[MAX_PWD_LEN_CHAR-1]   = '\0';

            ESP_LOGI(TAG, "  JSON[%d]: SSID=\"%s\", pwd=\"%s\"",
                     i, list[i].ssid, list[i].pwd);
        }
    }

    cJSON_Delete(root);
    *out_count = count;
    return list;
}

/* ----------------------------------------------------------------------------
   Event handler per Wi‑Fi e IP
   arg = EventGroupHandle_t
   ---------------------------------------------------------------------------- */
static void event_handler(void *arg,
                          esp_event_base_t base,
                          int32_t id,
                          void *data)
{
    EventGroupHandle_t grp = (EventGroupHandle_t)arg;

    if (base == WIFI_EVENT) {
        switch (id) {
            case WIFI_EVENT_STA_START:
                ESP_LOGI(TAG, "Station started");
                xEventGroupSetBits(grp, WIFI_STARTED_BIT);
                break;
            case WIFI_EVENT_STA_DISCONNECTED:
                if (retry_count < RETRY_NUM) {
                    esp_wifi_connect();
                    retry_count++;
                    ESP_LOGW(TAG, "Retry Wi‑Fi connect %d/%d",
                             retry_count, RETRY_NUM);
                } else {
                    ESP_LOGE(TAG, "Exceeded max retries");
                }
                break;
            default:
                break;
        }
    }
    else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t *evt = (ip_event_got_ip_t*)data;
        snprintf(ip_address, sizeof(ip_address),
                 IPSTR, IP2STR(&evt->ip_info.ip));
        ESP_LOGI(TAG, "Got IP: %s", ip_address);
        xEventGroupSetBits(grp, WIFI_CONNECTED_BIT);
    }
}

/* ----------------------------------------------------------------------------
   Scansiona, seleziona AP noto e riempie SSID/PWD
   ---------------------------------------------------------------------------- */
static bool wifi_scan_and_select(void)
{
    // 1) crea EventGroup
    wifi_event_group = xEventGroupCreate();

    // 2) registra handler sul default loop
    ESP_ERROR_CHECK( esp_event_handler_instance_register(
        WIFI_EVENT, WIFI_EVENT_STA_START,
        event_handler, wifi_event_group, NULL) );
    ESP_ERROR_CHECK( esp_event_handler_instance_register(
        WIFI_EVENT, WIFI_EVENT_STA_DISCONNECTED,
        event_handler, wifi_event_group, NULL) );
    ESP_ERROR_CHECK( esp_event_handler_instance_register(
        IP_EVENT,   IP_EVENT_STA_GOT_IP,
        event_handler, wifi_event_group, NULL) );

    // 3) avvia driver Wi‑Fi
    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK( esp_wifi_init(&init_cfg) );
    ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
    ESP_ERROR_CHECK( esp_wifi_start() );

    // 4) aspetto il bit STA_START
    xEventGroupWaitBits(wifi_event_group,
                        WIFI_STARTED_BIT,
                        pdTRUE,   // clear after
                        pdFALSE,  // wait any
                        portMAX_DELAY);

    // 5) scan bloccante
    ESP_ERROR_CHECK( esp_wifi_scan_start(NULL, true) );

    // 6) quanti AP sono stati trovati?
    uint16_t ap_count = 0;
    ESP_ERROR_CHECK( esp_wifi_scan_get_ap_num(&ap_count) );
    ESP_LOGI(TAG, "Scan found %d AP(s)", ap_count);

    // 7) alloco e recupero records
    wifi_ap_record_t *ap_records =
        malloc(sizeof(*ap_records) * ap_count);
    ESP_ERROR_CHECK( esp_wifi_scan_get_ap_records(
        &ap_count, ap_records) );

    // debug dump
    for (int i = 0; i < ap_count; ++i) {
        ESP_LOGI(TAG, "[%2d] %s (RSSI %d)",
                 i, ap_records[i].ssid, ap_records[i].rssi);
    }

    // 8) leggo JSON credenziali
    int json_count = 0;
    wifi_t *creds = file_wifi(&json_count);
    if (!creds) {
        ESP_LOGE(TAG, "file_wifi() failed");
        free(ap_records);
        return false;
    }

    // 9) match AP <-> credenziali
    bool found = false;
    for (int i = 0; i < ap_count && !found; ++i) {
        for (int j = 0; j < json_count; ++j) {
            if (strcmp((char*)ap_records[i].ssid,
                       creds[j].ssid) == 0)
            {
                strncpy((char*)SSID, creds[j].ssid,
                        sizeof(SSID)-1);
                strncpy((char*)PWD,  creds[j].pwd,
                        sizeof(PWD)-1);
                ESP_LOGI(TAG, "Selected SSID=\"%s\"", SSID);
                found = true;
                break;
            }
        }
    }

    free(creds);
    free(ap_records);
    return found;
}

/* ----------------------------------------------------------------------------
   Connette all’AP già selezionato e aspetta l’IP
   ---------------------------------------------------------------------------- */
static bool wifi_connect_and_wait(void)
{
    wifi_config_t cfg = { 0 };
    memcpy(cfg.sta.ssid,     SSID, sizeof(cfg.sta.ssid));
    memcpy(cfg.sta.password, PWD,  sizeof(cfg.sta.password));

    ESP_ERROR_CHECK( esp_wifi_set_config(WIFI_IF_STA, &cfg) );
    ESP_ERROR_CHECK( esp_wifi_connect() );

    EventBits_t bits = xEventGroupWaitBits(
        wifi_event_group,
        WIFI_CONNECTED_BIT,
        pdFALSE, pdTRUE,
        pdMS_TO_TICKS(20000));
    ESP_ERROR_CHECK(mdns_init());
    ESP_ERROR_CHECK(mdns_hostname_set("esp32"));        // esp32.local
    ESP_ERROR_CHECK(mdns_instance_name_set("ESP32 mDNS"));
    // 4. Add HTTP service (_http._tcp:80)
    ESP_ERROR_CHECK(mdns_service_add("web_server", "_https", "_tcp", 443, NULL, 0));    
    return (bits & WIFI_CONNECTED_BIT) != 0;
}

static void sntp_init_and_wait(void) {
    ESP_LOGI(TAG, "Initializing SNTP");
    esp_sntp_setoperatingmode(ESP_SNTP_OPMODE_POLL);
    esp_sntp_setservername(0, "pool.ntp.org");
    esp_sntp_init();

    time_t now = 0;
    struct tm timeinfo = { 0 };
    int retry = 0;
    const int retry_count = 10;
    while (retry < retry_count) {
        time(&now);
        localtime_r(&now, &timeinfo);
        if (timeinfo.tm_year >= (2020 - 1900)) {
            ESP_LOGI(TAG, "Time synchronized: %s", asctime(&timeinfo));
            return;
        }
        ESP_LOGI(TAG, "Waiting for system time...");
        vTaskDelay(pdMS_TO_TICKS(2000));
        retry++;
    }
    ESP_LOGW(TAG, "SNTP time sync failed");
}

static void fatal_mbedtls(const char *msg, int err) {
    char buf[128];
    mbedtls_strerror(err, buf, sizeof(buf));
    ESP_LOGE(TAG, "%s: -0x%04X: %s", msg, -err, buf);
    abort();
}


bool check_cert_sdcard(const char *filename)
{
    size_t pem_len;
    char* pem = NULL;
    read_file(filename,&pem,&pem_len);
    if (!pem) {
        ESP_LOGE(TAG,"NO DATA CERTIFICATE");
        return false;
    }

    // Parse PEM into X.509 structure
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int ret = mbedtls_x509_crt_parse(&cert,(const unsigned char*) pem, pem_len + 1);
    free(pem);
    if (ret != 0) {
        ESP_LOGE(TAG, "crt_parse failed: -0x%04x", -ret);
        mbedtls_x509_crt_free(&cert);
        return false;
    }

    // Check “not after”
    if (mbedtls_x509_time_is_past(&cert.valid_to)) {
        ESP_LOGW(TAG, "Certificate has expired");
        return false;
    }

    char buf_from[32], buf_to[32];
    snprintf(buf_from, sizeof(buf_from),
             "%04u-%02u-%02u %02u:%02u:%02u UTC",
             cert.valid_from.year, cert.valid_from.mon, cert.valid_from.day,
             cert.valid_from.hour, cert.valid_from.min, cert.valid_from.sec);
    snprintf(buf_to, sizeof(buf_to),
             "%04u-%02u-%02u %02u:%02u:%02u UTC",
             cert.valid_to.year, cert.valid_to.mon, cert.valid_to.day,
             cert.valid_to.hour, cert.valid_to.min, cert.valid_to.sec);

    ESP_LOGI(TAG, "Validity period: from %s to %s", buf_from, buf_to);

    mbedtls_x509_crt_free(&cert);
    return true;
}

bool brevo_cert_to_sd(mbedtls_ssl_context *ssl, const char *path)
{
    const mbedtls_x509_crt *chain = mbedtls_ssl_get_peer_cert(ssl);
    if (!chain) {
        ESP_LOGE(TAG, "Nessun certificato ricevuto");
        return false;
    }

    const char *hdr = "-----BEGIN CERTIFICATE-----\n";
    const char *ftr = "-----END CERTIFICATE-----\n";
    size_t total_len = 0;
    size_t olen;
    int ret;

    // 1) Misura preventiva: calcola bytes necessari per ogni CRT
    for (const mbedtls_x509_crt *crt = chain; crt; crt = crt->next) {
        olen = 0;
        ret = mbedtls_pem_write_buffer(
            hdr, ftr,
            crt->raw.p, crt->raw.len,
            NULL, 0, &olen
        );
        if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL && ret != 0) {
            ESP_LOGE(TAG, "Errore misura PEM: -0x%04X", -ret);
            return false;
        }
        total_len += olen;
    }
    ESP_LOGI(TAG, "Dimensione totale PEM: %u byte", (unsigned)total_len);

    // 2) Apri e pre‑alloca il file
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0666);
    if (fd < 0) {
        ESP_LOGE(TAG, "open(%s) failed: %s", path, strerror(errno));
        return false;
    }
    if (ftruncate(fd, (off_t)total_len) != 0) {
        ESP_LOGE(TAG, "ftruncate failed: %s", strerror(errno));
        close(fd);
        return false;
    }

    // 3) Alloca buffer e genera PEM
    unsigned char *buf = malloc(total_len);
    if (!buf) {
        ESP_LOGE(TAG, "malloc(%u) failed", (unsigned)total_len);
        close(fd);
        return false;
    }

    size_t write_off = 0;
    for (const mbedtls_x509_crt *crt = chain; crt; crt = crt->next) {
        size_t this_len = 0;
        ret = mbedtls_pem_write_buffer(
            hdr, ftr,
            crt->raw.p, crt->raw.len,
            buf + write_off, total_len - write_off, &this_len
        );
        if (ret != 0) {
            ESP_LOGE(TAG, "Errore PEM write: -0x%04X", -ret);
            free(buf);
            close(fd);
            return false;
        }
        write_off += this_len;
    }

    // 4) Scrive su file
    if (write(fd, buf, write_off) != (ssize_t)write_off) {
        ESP_LOGE(TAG, "write failed: %s", strerror(errno));
        free(buf);
        close(fd);
        return false;
    }

    free(buf);
    close(fd);
    ESP_LOGI(TAG, "Certificato salvato in %s (%u byte)", path, (unsigned)total_len);
    return true;
}

bool get_certificate_brevo(const char* filename){
    // Sync time for cert checks
    sntp_init_and_wait();
    bool choice = false;

    // mbedTLS contexts
    mbedtls_net_context       server_fd;
    mbedtls_ssl_context       ssl;
    mbedtls_ssl_config        conf;
    mbedtls_entropy_context   entropy;
    mbedtls_ctr_drbg_context  ctr_drbg;

    mbedtls_net_init(&server_fd);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    // Seed RNG
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0);
    if (ret != 0) fatal_mbedtls("DRBG seed failed", ret);

    // Configure SSL: no CA verification, only expiration check
    ret = mbedtls_ssl_config_defaults(&conf,
                                      MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM,
                                      MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) fatal_mbedtls("ssl_config_defaults", ret);

    // Provide RNG callback to SSL
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);

    ret = mbedtls_ssl_setup(&ssl, &conf);
    if (ret != 0) fatal_mbedtls("ssl_setup", ret);

    ret = mbedtls_ssl_set_hostname(&ssl, BREVO_HOST);
    if (ret != 0) fatal_mbedtls("set_hostname", ret);

    ESP_LOGI(TAG, "Connecting to %s:%s...", BREVO_HOST, BREVO_PORT);
    ret = mbedtls_net_connect(&server_fd, BREVO_HOST, BREVO_PORT, MBEDTLS_NET_PROTO_TCP);
    if (ret != 0) fatal_mbedtls("net_connect", ret);
    mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, NULL);

    ESP_LOGI(TAG, "Starting TLS handshake...");
    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            fatal_mbedtls("ssl_handshake", ret);
        }
    }
    ESP_LOGI(TAG, "Handshake complete");

    // Retrieve peer cert and check validity
    const mbedtls_x509_crt *peer = mbedtls_ssl_get_peer_cert(&ssl);
    if (peer == NULL) {
        ESP_LOGE(TAG, "No server certificate received");
        goto cleanup;
    }

    const mbedtls_x509_time *from = &peer->valid_from;
    const mbedtls_x509_time *to   = &peer->valid_to;
    char buf_from[32], buf_to[32];
    snprintf(buf_from, sizeof(buf_from), "%04d-%02d-%02d %02d:%02d:%02d",
             from->year, from->mon, from->day, from->hour, from->min, from->sec);
    snprintf(buf_to,   sizeof(buf_to),   "%04d-%02d-%02d %02d:%02d:%02d",
             to->year,   to->mon,   to->day,   to->hour,   to->min,   to->sec);

    ESP_LOGI(TAG, "Cert valid from: %s", buf_from);
    ESP_LOGI(TAG, "Cert valid to  : %s", buf_to);

    if (mbedtls_x509_time_is_future(from)) {
        ESP_LOGE(TAG, "Certificate not yet valid");
    } else if (mbedtls_x509_time_is_past(to)) {
        ESP_LOGE(TAG, "Certificate has expired");
    } else {
        ESP_LOGI(TAG, "Certificate is currently valid");
        if(file_exsist(MOUNT_POINT"/CERT/BREVO_~1.PEM")){
            choice = true;
        }else{
            if (!brevo_cert_to_sd(&ssl, filename)) {
                ESP_LOGE(TAG, "Impossibile salvare certificato");
            } else {
                choice = true;
                ESP_LOGI(TAG, "Certificato correttamente salvato");
            }
        }
        
        choice = true;
    }
    goto cleanup;

cleanup:
    mbedtls_ssl_close_notify(&ssl);
    mbedtls_net_free(&server_fd);
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    ESP_LOGI(TAG, "Done");
    return choice;
}

static void fmt_x509_time(const mbedtls_x509_time *t, char *buf, size_t len)
{
    snprintf(buf, len, "%04u-%02u-%02u %02u:%02u:%02u UTC",
             t->year, t->mon, t->day,
             t->hour, t->min, t->sec);
}

bool get_certificate_root(const char* filename){
    
    // 2) prepara e apri connessione TLS
    esp_tls_cfg_t tls_cfg = { 0 };
    esp_tls_t *tls = esp_tls_init();                   // ✱ allocate handle :contentReference[oaicite:6]{index=6}
    if (!tls) {

        ESP_LOGE(TAG, "esp_tls_init failed");
        return false;
    }
    int ret = esp_tls_conn_new_sync(
                "api.brevo.com", strlen("api.brevo.com"), 443,
                &tls_cfg, tls                        // now matches new signature :contentReference[oaicite:7]{index=7}
              );
    if (ret <= 0) {
        ESP_LOGE(TAG, "TLS handshake failed: %d", ret);
        esp_tls_conn_destroy(tls);
        return false;
    }
    ESP_LOGI(TAG, "TLS handshake ok");

    // 3) estrai il mbedTLS SSL context
    mbedtls_ssl_context *ssl = (mbedtls_ssl_context*)esp_tls_get_ssl_context(tls);
    if (!ssl) {
        ESP_LOGE(TAG, "cannot get mbedtls context");
        esp_tls_conn_destroy(tls);
        return false;
    }

    // 4) prendi la catena e cammina fino al root
    const mbedtls_x509_crt *chain = mbedtls_ssl_get_peer_cert(ssl);
    if (!chain) {
        ESP_LOGE(TAG, "no peer certificate");
        esp_tls_conn_destroy(tls);
        return false;
    }
    const mbedtls_x509_crt *root = chain;
    while (root->next) root = root->next;

    // 5) log DER‑size e validità
    size_t der_size = root->raw.len;
    char from[32], to[32];
    fmt_x509_time(&root->valid_from, from, sizeof(from));
    fmt_x509_time(&root->valid_to,   to,   sizeof(to));
    ESP_LOGI(TAG, "Root CA DER size: %d bytes", (int)der_size);
    ESP_LOGI(TAG, "Validity: %s → %s", from, to);

    // 6) PEM‑encode
    unsigned char pem[4096];
    size_t pem_len = 0;
    ret = mbedtls_pem_write_buffer(
              "-----BEGIN CERTIFICATE-----\n",
              "-----END CERTIFICATE-----\n",
              root->raw.p, root->raw.len,
              pem, sizeof(pem), &pem_len
          );
    if (ret != 0) {
        ESP_LOGE(TAG, "PEM encode failed: -0x%04x", -ret);
        esp_tls_conn_destroy(tls);
        return false;
    }
    ESP_LOGI(TAG, "PEM size: %d bytes", (int)pem_len);

    // 7) salva su SPIFFS
    FILE *f = fopen(filename, "w");
    if (!f) {
        ESP_LOGE(TAG, "open failed");
        esp_tls_conn_destroy(tls);
        return false;
    }
    size_t written = fwrite(pem, 1, pem_len, f);
    fclose(f);
    if (written != pem_len) {
        ESP_LOGE(TAG, "write error %d of %d", (int)written, (int)pem_len);
        esp_tls_conn_destroy(tls);
        return false;
    }
    ESP_LOGI(TAG, "Saved %d‑byte PEM to %s", (int)written, MOUNT_POINT"/");

    // cleanup
    esp_tls_conn_destroy(tls);
    return true;
}

bool init_certificate(){
    if(!check_cert_sdcard(MOUNT_POINT"/CERT/BREVO_~1.PEM")){
        if(!get_certificate_brevo(MOUNT_POINT"/CERT/BREVO_~1.PEM")){
            return false;
        }
    }
    if(!check_cert_sdcard(MOUNT_POINT"/CERT/ISRGRO~1.PEM")){
        if(!get_certificate_root(MOUNT_POINT"/CERT/ISRGRO~1.PEM")){
            return false;
        }
    }
    return true;
}