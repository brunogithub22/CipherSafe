#include "lcd_display.c"


bool file_exsist(const char* path){
    FILE *fp = fopen(path, "r");
    bool is_exist = false;
    if (fp != NULL)
    {
        is_exist = true;
        fclose(fp); // close the file
    }
    return is_exist;
}

// Read file from SD card into heap buffer
static bool read_file(const char *path, char **buf, size_t *len)
{
    if(file_exsist(path)){
        FILE *f = fopen(path, "rb");
        if (!f) {
            ESP_LOGE(TAG, "Failed to open file %s", path);
            return false;
        }
        fseek(f, 0, SEEK_END);
        *len = ftell(f);
        fseek(f, 0, SEEK_SET);
 
        *buf = malloc(*len + 1);
        if (!*buf) {
            fclose(f);
            ESP_LOGE(TAG, "Failed to allocate buffer");
            return false;
        }
        fread(*buf, 1, *len, f);
        (*buf)[*len] = '\0';
        fclose(f);
        ESP_LOGI(TAG, "Read %d bytes from %s", (int)*len, path);
        return true;
    }else{
        return false;
    }
    
}

bool fun_card(){
    ESP_LOGI(TAG, "Initializing SD card");

    slot_config.gpio_cs = PIN_NUM_CS;
    slot_config.host_id = host.slot;
    host.max_freq_khz = 500;
    
    // Inizializza il bus SPI
    ret = spi_bus_initialize(host.slot, &bus_cfg, SPI_DMA_CH_AUTO);
    if (ret != ESP_OK) {
        //ESP_LOGE(TAG, "Failed to initialize SPI bus: %s", esp_err_to_name(ret));
        return false;
    }
    
    return true;
}


bool sd_mount(){
    
    // Monta il filesystem FAT utilizzando l'interfaccia SPI
    ret = esp_vfs_fat_sdspi_mount(MOUNT_POINT, &host, &slot_config, &mount_config, &card);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to mount filesystem. Error: %s", esp_err_to_name(ret));
        return false;
    }
    mounted = true;
    ESP_LOGI(TAG, "Filesystem mounted successfully");
    return true;
}

bool sd_dir_exists(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0) {
        // errno impostato: file o dir non esiste o errore I/O
        ESP_LOGD(TAG, "stat(%s) failed: %s", path, strerror(errno));
        return false;
    }
    if (S_ISDIR(st.st_mode)) {
        ESP_LOGI(TAG, "Directory exists: %s", path);
        return true;
    } else {
        ESP_LOGW(TAG, "Path exists but is not a directory: %s", path);
        return false;
    }
}

bool name_fat(const char* path, const char* long_name, char* out_sfn, size_t out_len) {
    FRESULT res;
    FF_DIR dir;
    FILINFO fno;

    // Apri la directory specificata
    res = f_opendir(&dir, path);
    if (res != FR_OK) {
        printf("Errore f_opendir: %d\n", res);
        return false;
    }

    // Leggi le voci della directory
    while (true) {
        res = f_readdir(&dir, &fno);
        if (res != FR_OK) {
            printf("Errore f_readdir: %d\n", res);
            break;
        }
        if (fno.fname[0] == '\0') {
            // Fine della directory
            break;
        }

        // Verifica se è una directory
        if (fno.fattrib & AM_DIR) {
            printf("Trovata directory: %s\n", fno.fname);

            // Confronta il nome lungo
            if (strcasecmp(fno.fname, long_name) == 0) {
                const char* src = fno.altname[0] ? fno.altname : fno.fname;
                printf("\ndirectory: %s\n",src);
                strncpy(out_sfn, src, out_len - 1);
                out_sfn[out_len - 1] = '\0';
                f_closedir(&dir);
                return true;
            }
        }
    }

    f_closedir(&dir);
    return false;
}

bool name_fat_file(const char* dir_path,
                   const char* long_name,
                   char* out_sfn,
                   size_t out_len)
{
    FRESULT res;
    FF_DIR dir;
    FILINFO fno;

    // 1) Apri la directory
    res = f_opendir(&dir, dir_path);
    if (res != FR_OK) {
        printf("Errore f_opendir(\"%s\"): %d\n", dir_path, res);
        return false;
    }

    // 2) Scorri tutte le voci con f_readdir
    while ((res = f_readdir(&dir, &fno)) == FR_OK && fno.fname[0]) {
        // fno.fname è sempre il nome breve (8.3) null-terminated
        // fno.altname, se compilato, contiene l'8.3 alternativo (o è vuoto)

        // Confronto case-insensitive: long_name vs fname (SFN) o altname
        if (strcasecmp(fno.fname, long_name) == 0 ||
            (fno.altname[0] && strcasecmp(fno.altname, long_name) == 0))
        {
            const char *sfn = (fno.altname[0] ? fno.altname : fno.fname);

            strncpy(out_sfn, sfn, out_len - 1);
            out_sfn[out_len - 1] = '\0';

            f_closedir(&dir);
            return true;
        }
    }

    // 4) Se esce per errore di readdir, loggalo
    if (res != FR_OK) {
        printf("Errore f_readdir(\"%s\"): %d\n", dir_path, res);
    }

    f_closedir(&dir);
    return false;
}


bool create_folder( char* parent, char* name) {
    if (!sd_dir_exists(parent)) {
        fprintf(stderr, "Cartella padre non trovata: %s\n", parent);
        return false;
    }

    size_t path1_len = strlen(parent);
    size_t path2_len = strlen(name);
    bool need_sep = (parent[path1_len - 1] != '/');
    // +1 per '/' se serve, +1 per '\0'
    size_t total_len = path1_len + (need_sep ? 1 : 0) + path2_len + 1;

    char *new_path = malloc(total_len);
    if (!new_path) {
        perror("malloc");             // best practice: log dell’errore
        return false;                 // non return ""
    }

    // Usa snprintf per concatenare in modo sicuro  
    if (need_sep) {
        snprintf(new_path, total_len, "%s/%s", parent, name);
    } else {
        snprintf(new_path, total_len, "%s%s", parent, name);
    }

    // Prova a creare la cartella
    int res = mkdir(new_path, 0777);
    if (res == 0) {
        printf("Cartella creata: %s\n", new_path);
    } else if (errno == EEXIST) {
        printf("La cartella esiste già: %s\n", new_path);
    } else {
        printf("Errore creazione cartella %s: %s\n",
               new_path, strerror(errno));
        free(new_path);               // libera anche in caso di errore
        return false;
    }

    free(new_path);                   // libera dopo l’uso :contentReference[oaicite:6]{index=6}
    return true;
}

// Inizializza
int dynstr_init(dynstr_t *s) {
    s->cap = INITIAL_CAPACITY;
    s->len = 0;
    s->buf = malloc(s->cap);
    if (!s->buf) return -1;
    s->buf[0] = '\0';
    return 0;
}

// Estende se necessario
int dynstr_ensure(dynstr_t *s, size_t extra) {
    if (s->len + extra + 1 > s->cap) {
        // raddoppia finché non basta
        size_t newcap = s->cap;
        while (newcap < s->len + extra + 1) {
            newcap *= 2;
        }
        char *nb = realloc(s->buf, newcap);
        if (!nb) return -1;
        s->buf = nb;
        s->cap = newcap;
    }
    return 0;
}

// Aggiunge una parte
int dynstr_append(dynstr_t *s, const char *part) {
    size_t plen = strlen(part);
    if (dynstr_ensure(s, plen) != 0) return -1;
    memcpy(s->buf + s->len, part, plen);
    s->len += plen;
    s->buf[s->len] = '\0';
    return 0;
}

// Libera
void dynstr_free(dynstr_t *s) {
    free(s->buf);
    s->buf = NULL;
    s->len = s->cap = 0;
}


bool sd_unmount(){
    esp_vfs_fat_sdcard_unmount(MOUNT_POINT, card);
    ESP_LOGI(TAG, "Scheda SD smontata");
    mounted = false;
    return true;
}

// Function to generate a secure AES IV
void generate_aes_iv(unsigned char *iv) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "esp32_aes_iv_gen";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,(const unsigned char *)pers, strlen(pers));
    mbedtls_ctr_drbg_random(&ctr_drbg, iv, AES_BLOCK_SIZE);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}


// Generate random IV
static int generate_iv(unsigned char iv[AES_BLOCK_SIZE]) {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "aes_iv_gen";
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    if (mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                              (const unsigned char *) pers, strlen(pers)) != 0) {
        return -1;
    }
    if (mbedtls_ctr_drbg_random(&ctr_drbg, iv, AES_BLOCK_SIZE) != 0) {
        return -1;
    }
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    return 0;
}

int encrypt_file(const char *input_file,
                 const char *output_file,
                 const unsigned char *key)
{
    int ret = 0;
    FILE *fin  = NULL;
    FILE *fout = NULL;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char *inbuf  = NULL;
    unsigned char *outbuf = NULL;
    size_t inlen, olen;

    mbedtls_cipher_context_t ctx;
    const mbedtls_cipher_info_t *info = NULL;

    /* 1) Apertura file */
    fin  = fopen(input_file,  "rb");
    fout = fopen(output_file, "wb");
    if (!fin || !fout) {
        ret = -1;
        goto cleanup;
    }

    /* 2) Genera IV e scrivilo in testa al file di destinazione */
    if (generate_iv(iv) != 0 ||
        fwrite(iv, 1, AES_BLOCK_SIZE, fout) != AES_BLOCK_SIZE) {
        ret = -1;
        goto cleanup;
    }

    /* 3) Inizializza e configura il contesto cipher */
    mbedtls_cipher_init(&ctx);
    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
    if ( info == NULL
      || mbedtls_cipher_setup(&ctx, info) != 0
      || mbedtls_cipher_setkey(&ctx, key, AES_KEY_SIZE * 8, MBEDTLS_ENCRYPT) != 0
      || mbedtls_cipher_set_iv(&ctx, iv, AES_BLOCK_SIZE) != 0
      /* ← abilita padding PKCS#7, default se definito, ma meglio esplicitarlo */ 
      || mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_PKCS7) != 0  /* :contentReference[oaicite:0]{index=0} */
      || mbedtls_cipher_reset(&ctx) != 0 )
    {
        ret = -1;
        goto cleanup;
    }

    /* 4) Alloca buffer di input/output */
    inbuf  = malloc(BUFFER_SIZE);
    outbuf = malloc(BUFFER_SIZE + AES_BLOCK_SIZE);
    if (!inbuf || !outbuf) {
        ret = -1;
        goto cleanup;
    }

    /* 5) Streaming encrypt */
    while ((inlen = fread(inbuf, 1, BUFFER_SIZE, fin)) > 0) {
        if (mbedtls_cipher_update(&ctx, inbuf, inlen, outbuf, &olen) != 0 ||
            fwrite(outbuf, 1, olen, fout) != olen) {
            ret = -1;
            goto cleanup;
        }
    }

    /* 6) Finish: padding e ultimo blocco */
    if (mbedtls_cipher_finish(&ctx, outbuf, &olen) != 0 ||
        fwrite(outbuf, 1, olen, fout) != olen) {
        ret = -1;
        goto cleanup;
    }

cleanup:
    /* 7) Rilascio risorse */
    mbedtls_cipher_free(&ctx);
    if (inbuf)  free(inbuf);
    if (outbuf) free(outbuf);
    if (fin)    fclose(fin);
    if (fout)   fclose(fout);

    return ret;
}

int decrypt_file(const char *input_file,
                 const char *output_file,
                 const unsigned char *key)
{
    int ret = 0;
    FILE *fin  = NULL;
    FILE *fout = NULL;
    unsigned char iv[AES_BLOCK_SIZE];
    unsigned char *inbuf  = NULL;
    unsigned char *outbuf = NULL;
    size_t inlen, olen;

    mbedtls_cipher_context_t ctx;
    const mbedtls_cipher_info_t *info = NULL;

    /* 1) Apertura file */
    fin  = fopen(input_file,  "rb");
    fout = fopen(output_file, "wb");
    if (!fin || !fout) {
        ret = -1;
        goto cleanup;
    }

    /* 2) Leggi IV in testa al file */
    if (fread(iv, 1, AES_BLOCK_SIZE, fin) != AES_BLOCK_SIZE) {
        ret = -1;
        goto cleanup;
    }

    /* 3) Inizializza e configura il contesto cipher */
    mbedtls_cipher_init(&ctx);
    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_CBC);
    if ( info == NULL
      || mbedtls_cipher_setup(&ctx, info) != 0
      || mbedtls_cipher_setkey(&ctx, key, AES_KEY_SIZE * 8, MBEDTLS_DECRYPT) != 0
      || mbedtls_cipher_set_iv(&ctx, iv, AES_BLOCK_SIZE) != 0
      /* ← abilita padding PKCS#7 per poter rimuovere correttamente il padding al finish */
      || mbedtls_cipher_set_padding_mode(&ctx, MBEDTLS_PADDING_PKCS7) != 0
      || mbedtls_cipher_reset(&ctx) != 0 )
    {
        ret = -1;
        goto cleanup;
    }

    /* 4) Alloca buffer di input/output */
    inbuf  = malloc(BUFFER_SIZE + AES_BLOCK_SIZE);
    outbuf = malloc(BUFFER_SIZE + AES_BLOCK_SIZE);
    if (!inbuf || !outbuf) {
        ret = -1;
        goto cleanup;
    }

    /* 5) Streaming decrypt */
    while ((inlen = fread(inbuf, 1, BUFFER_SIZE + AES_BLOCK_SIZE, fin)) > 0) {
        if (mbedtls_cipher_update(&ctx, inbuf, inlen, outbuf, &olen) != 0 ||
            fwrite(outbuf, 1, olen, fout) != olen) {
            ret = -1;
            goto cleanup;
        }
    }

    /* 6) Finish: rimuovi padding e scrivi ultimo blocco */
    if (mbedtls_cipher_finish(&ctx, outbuf, &olen) != 0 ||
        fwrite(outbuf, 1, olen, fout) != olen) {
        ret = -1;
        goto cleanup;
    }

cleanup:
    /* 7) Rilascio risorse */
    mbedtls_cipher_free(&ctx);
    if (inbuf)  free(inbuf);
    if (outbuf) free(outbuf);
    if (fin)    fclose(fin);
    if (fout)   fclose(fout);

    return ret;
}


// Function to create a SHA-256 hash key from input data
void create_key(const unsigned char *input_data, unsigned char *sha256_hash) {
    // Use strlen() instead of sizeof() because input_data is a pointer
    size_t size_input_data = strlen((const char *)input_data);

    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);  // 0 for SHA-256
    mbedtls_sha256_update(&ctx, input_data, size_input_data);
    mbedtls_sha256_finish(&ctx, sha256_hash);
    mbedtls_sha256_free(&ctx);
}

// ISR: disabilita e segnala il task
static void IRAM_ATTR event_interrupt(void *arg) {
    uint32_t gpio_num = (uint32_t) arg;
    gpio_intr_disable(gpio_num);           // blocca edge successivi
    xSemaphoreGiveFromISR(buttonSemaphore, NULL);
}

// Configura pull-up e falling edge
static void button_configuration(int gpio) {
    gpio_config_t config = {
        .pin_bit_mask   = (1ULL << gpio),
        .mode           = GPIO_MODE_INPUT,
        .pull_up_en     = GPIO_PULLUP_ENABLE,
        .pull_down_en   = GPIO_PULLDOWN_DISABLE,
        .intr_type      = GPIO_INTR_NEGEDGE
    };
    gpio_config(&config);
    gpio_install_isr_service(0);
    gpio_isr_handler_add(gpio, event_interrupt, (void*) gpio);
}

// Task di gestione: debounce + wait rilascio
static void button_task(void *arg) {
    while (1) {
        if (xSemaphoreTake(buttonSemaphore, portMAX_DELAY) == pdTRUE) {
            portENTER_CRITICAL(&mux);
            count++;
            portEXIT_CRITICAL(&mux);
            ESP_LOGI("ESP32", "Pulsante premuto! %d volte", count);

            if(mounted){
                if(sd_unmount()){}
            }
            // Debounce software
            vTaskDelay(pdMS_TO_TICKS(200));

            // Aspetta che il pulsante sia rilasciato (HIGH)
            while (gpio_get_level(BUTTON_GPIO) == 0) {
                vTaskDelay(pdMS_TO_TICKS(10));
            }

            // Ri-abilita l’interrupt per il prossimo click
            gpio_intr_enable(BUTTON_GPIO);
        }
    }
}

static bool generate_token(char *out, size_t out_len) {
    if (out_len < TOKEN_STR_LEN) {
        return false;
    }
    uint8_t buf[TOKEN_BYTES];
    // Riempie buf[] con TOKEN_BYTES byte casuali veri
    esp_fill_random(buf, sizeof(buf));  // :contentReference[oaicite:2]{index=2}

    // Converte ogni byte in due caratteri esadecimali
    for (int i = 0; i < TOKEN_BYTES; i++) {
        // sprintf scrive "%02x" → esadecimale a due cifre
        sprintf(&out[i * 2], "%02x", buf[i]);
    }
    out[TOKEN_STR_LEN - 1] = '\0';  // terminatore stringa
    return true;
}

// Genera un ID esadecimale di 32 caratteri più terminatore
static void generate_random_id(char *out) {
    uint8_t buf[16];
    esp_fill_random(buf, sizeof(buf));
    for (int i = 0; i < 16; i++) {
        sprintf(out + i*2, "%02x", buf[i]);
    }
    out[32] = '\0';
}

static void to_hex(const unsigned char *in, size_t len, char *out) {
    static const char hex_digits[] = "0123456789abcdef";
    for (size_t i = 0; i < len; ++i) {
        out[i * 2]     = hex_digits[(in[i] >> 4) & 0xF];
        out[i * 2 + 1] = hex_digits[in[i] & 0xF];
    }
    out[len * 2] = '\0';
}

char* digest(const char* input){
    unsigned char bin_hash[SHA256_BIN_LEN];
    create_key((const unsigned char*)input, bin_hash);

    char *hex = malloc(SHA256_HEX_LEN);
    if (!hex) return NULL;

    to_hex(bin_hash, SHA256_BIN_LEN, hex);
    return hex;                         // chiamante deve free(hex) :contentReference[oaicite:9]{index=9}
}