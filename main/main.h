#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include <driver/gpio.h>
#include "esp_log.h"
#include "string.h"
#include "esp_event.h"
#include "freertos/semphr.h"
#include "nvs_flash.h"  
#include "mdns.h"
#include <stdio.h>
#include "esp_tls.h"  
#include "esp_system.h"
#include "esp_err.h"
#include "esp_vfs_fat.h"
#include "sdmmc_cmd.h"
#include "driver/spi_common.h"
#include "driver/sdspi_host.h"
#include <sys/stat.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include "mbedtls/aes.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/sha256.h"
#include "esp_vfs.h"
#include <ctype.h>
#include "esp_system.h"
#include "esp_https_server.h"
#include "esp_http_client.h"
#include "esp_vfs.h"
#include <fcntl.h>
#include <unistd.h>   // For close() and read()
#include <sys/stat.h> // For fstat()
#include <stdlib.h>   // For malloc() and free()
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "driver/i2c.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "driver/sdmmc_host.h"
#include "driver/sdmmc_defs.h"
#include "sdmmc_cmd.h"
#include <sys/unistd.h>
#include <fcntl.h>
#include "cJSON.h"
#include "esp_sntp.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#include "mbedtls/pem.h"  
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/x509_crt.h"
#include "mbedtls/error.h"
#include "mbedtls/base64.h"
#include "lwip/inet.h"
#include <fcntl.h>   
#include <dirent.h>
#include "ff.h"  

#define BREVO_HOST   "api.brevo.com"
#define BREVO_PORT   "443"

/* Imposta l'SSID e la password via configurazione di progetto, oppure impostali direttamente qui */
#define DEFAULT_SCAN_LIST_SIZE CONFIG_EXAMPLE_SCAN_LIST_SIZE

#define RETRY_NUM 5
#ifndef CONFIG_EXAMPLE_SCAN_LIST_SIZE
#define CONFIG_EXAMPLE_SCAN_LIST_SIZE 10
#endif
#define DEFAULT_SCAN_METHOD WIFI_FAST_SCAN
#define DEFAULT_SORT_METHOD WIFI_CONNECT_AP_BY_SIGNAL
#define DEFAULT_RSSI -70           // Esempio di soglia RSSI
#define DEFAULT_AUTHMODE WIFI_AUTH_WPA2_PSK

// Definisci i pin da utilizzare (modifica secondo il tuo hardware)
#define PIN_NUM_MISO 19
#define PIN_NUM_MOSI 23
#define PIN_NUM_CLK  18
#define PIN_NUM_CS   15
#define MOUNT_POINT "/sdcard"
// AES configuration
#define AES_KEY_SIZE 32   // AES-256 = 32 bytes (256 bits)
#define AES_BLOCK_SIZE 16 // AES block size (CBC mode)
#define BUFFER_SIZE 1024  // Process file in chunks
// Increase FILE_PATH_MAX to allow room for subdirectories.
#define FILE_PATH_MAX        (ESP_VFS_PATH_MAX + 128)
// Size for the scratch buffer in chunked mode.
#define SCRATCH_BUFSIZE      (10240)
// Maximum file size (in bytes) to serve using the fast (single-read) mode.
#define FAST_FILE_MAX        (1024 * 1024)  // 1 MB
// Context structure to store the base path for files and a scratch buffer.
// Helper macro to check file extension (case-insensitive)
#define CHECK_FILE_EXTENSION(filename, ext) (strcasecmp(&filename[strlen(filename) - strlen(ext)], ext) == 0)

// I2C configuration
#define I2C_SDA_GPIO       21
#define I2C_SCL_GPIO       22
#define I2C_PORT           I2C_NUM_0
#define I2C_FREQ_HZ        100000

// Address of PCF8574 on I2C bus (7-bit)
#define LCD_I2C_ADDRESS    0x27  // Replace with your scanned address

#ifndef ARRAY_SIZE
  #define ARRAY_SIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#define CHUNKED_THRESHOLD   (8 * 1024)   // still unused, but kept for reference
#define CHUNK_BUF_SIZE      (4 * 1024)   // 4 KiB streaming chunks

//———————————————————————————————————————————————————
// MIME lookup remains unchanged
typedef struct {
    const char *ext;
    const char *mime;
} mime_map_t;

esp_err_t ret;
sdmmc_card_t *card;
static const char *TAG = "HTTPS_SERVER_SD";
typedef struct {
    char base_path[ESP_VFS_PATH_MAX + 1];
    char scratch[SCRATCH_BUFSIZE];
} rest_server_context_t;

sdmmc_host_t host = SDSPI_HOST_DEFAULT();
esp_vfs_fat_mount_config_t mount_config = {
  .format_if_mount_failed = false,
  .max_files = 5,                     // Numero massimo di file aperti contemporaneamente
  .allocation_unit_size = 16 * 1024,   // Dimensione unità di allocazione
};

sdspi_device_config_t slot_config = SDSPI_DEVICE_CONFIG_DEFAULT();
 
// Configura il bus SPI
spi_bus_config_t bus_cfg = {
  .mosi_io_num = PIN_NUM_MOSI,
  .miso_io_num = PIN_NUM_MISO,
  .sclk_io_num = PIN_NUM_CLK,
  .quadwp_io_num = -1,      // non utilizzato
  .quadhd_io_num = -1,      // non utilizzato
  .max_transfer_sz = 4000,  // dimensione massima del trasferimento
};

#define MAX_UPLOADS 16

// Struttura per tenere in RAM i metadati di ogni sessione
typedef struct {
    char uploadId[33];
    char filename[64];
    char password[32];
    char archive[32];
    char author[32];
    int totalChunks;
    bool done;
    size_t cumulative_bytes; 
} upload_meta_t;

// Tabella statica in RAM
static upload_meta_t upload_table[MAX_UPLOADS];
static bool upload_done[MAX_UPLOADS];

bool mounted = false;

#define INITIAL_CAPACITY 64

typedef struct {
    char   *buf;       // puntatore al buffer
    size_t  len;       // lunghezza attuale della stringa
    size_t  cap;       // capacità allocata
} dynstr_t;

#define BUTTON_GPIO 22

static SemaphoreHandle_t buttonSemaphore;
static volatile int count = 0;
static portMUX_TYPE mux = portMUX_INITIALIZER_UNLOCKED;