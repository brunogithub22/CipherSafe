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