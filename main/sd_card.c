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

bool name_fat_file(const char* path, const char* long_name, char* out_sfn, size_t out_len) {
    FRESULT res;
    FILINFO fno;
    
    // Prepara la struttura FILINFO per ottenere anche l'altname (SFN)
#if _USE_LFN
    // Se _USE_LFN è abilitato, destinare buffer LFN a NULL per leggere solo altname
    fno.lfname = NULL;
    fno.lfsize = 0;
#endif

    // Prova a ottenere le informazioni sul file
    res = f_stat(path, &fno);
    if (res != FR_OK) {
        printf("Errore f_stat: %d\n", res);
        return false;
    }

    // Estrai il nome lungo dal FILINFO (dipende da _USE_LFN)
    const char* found_name = NULL;
#if _USE_LFN
    if (fno.lfname && strcmp(fno.lfname, long_name) == 0) {
        // Il nome lungo è uguale a quello cercato
        found_name = fno.altname[0] ? fno.altname : fno.lfname;
    } else
#endif
    {
        // Confronta il nome base (fname) con long_name
        if (strcasecmp(fno.fname, long_name) == 0) {
            found_name = fno.altname[0] ? fno.altname : fno.fname;
        }
    }

    if (!found_name) {
        // Il file con quel nome lungo non corrisponde
        return false;
    }

    // Copia in out_sfn tenendo conto della lunghezza massima
    strncpy(out_sfn, found_name, out_len - 1);
    out_sfn[out_len - 1] = '\0';
    return true;
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

// Sezione critica per accesso concorrente
void sd_enter_critical(void) {
    xSemaphoreTake(sd_mutex, portMAX_DELAY);
    if (ref_count++ == 0) {
        if(!sd_mount()){
            ESP_LOGE(TAG,"Errore mount");
        }
    }
    xSemaphoreGive(sd_mutex);
}

void sd_exit_critical(void) {
    xSemaphoreTake(sd_mutex, portMAX_DELAY);
    if (--ref_count == 0) {
        if(!sd_unmount()){
            ESP_LOGE(TAG,"Errore unmount");
        }
    }
    mounted = false;
    xSemaphoreGive(sd_mutex);
}


// Function to encrypt a file using AES-256-CBC
int encrypt_file(const char *input_file, const char *output_file, unsigned char *key) {
    FILE *fin = fopen(input_file, "rb");
    FILE *fout = fopen(output_file, "wb");
    if (!fin) {
        printf("Error opening input file.\n");
        return -1;
    }
    if (!fout) {
        printf("Error opening output file.\n");
        fclose(fin);
        return -1;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    generate_aes_iv(iv);

    // Write IV to the output file (needed for decryption)
    fwrite(iv, 1, AES_BLOCK_SIZE, fout);

    // Initialize AES context
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, AES_KEY_SIZE * 8); // Set AES-256 key

    // Allocate buffers on the heap to reduce stack usage
    unsigned char *buffer = malloc(BUFFER_SIZE + AES_BLOCK_SIZE);
    unsigned char *encrypted_buffer = malloc(BUFFER_SIZE + AES_BLOCK_SIZE);
    if (!buffer || !encrypted_buffer) {
        printf("Error allocating memory.\n");
        fclose(fin);
        fclose(fout);
        mbedtls_aes_free(&aes);
        free(buffer);
        free(encrypted_buffer);
        return -1;
    }

    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fin)) > 0) {
        // Determine padding length for the block (PKCS#7)
        size_t padding = AES_BLOCK_SIZE - (bytes_read % AES_BLOCK_SIZE);
        if (padding == 0) {
            padding = AES_BLOCK_SIZE;
        }
        // Apply padding to the buffer
        memset(buffer + bytes_read, padding, padding);
        bytes_read += padding;

        // Encrypt the block (CBC mode updates the IV)
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, bytes_read, iv, buffer, encrypted_buffer);
        fwrite(encrypted_buffer, 1, bytes_read, fout);
    }

    free(buffer);
    free(encrypted_buffer);
    fclose(fin);
    fclose(fout);
    mbedtls_aes_free(&aes);

    printf("File encrypted successfully!\n");
    return 0;
}

// Function to decrypt a file using AES-256-CBC
int decrypt_file(const char *input_file, const char *output_file, unsigned char *key) {
    FILE *fin = fopen(input_file, "rb");
    FILE *fout = fopen(output_file, "wb");
    if (!fin || !fout) {
        printf("Error opening files.\n");
        if(fin) fclose(fin);
        if(fout) fclose(fout);
        return -1;
    }

    unsigned char iv[AES_BLOCK_SIZE];
    // Read the IV from the encrypted file (first block)
    fread(iv, 1, AES_BLOCK_SIZE, fin);

    // Initialize AES context for decryption
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, AES_KEY_SIZE * 8);

    // Allocate buffers on the heap
    unsigned char *buffer = malloc(BUFFER_SIZE + AES_BLOCK_SIZE);
    unsigned char *decrypted_buffer = malloc(BUFFER_SIZE + AES_BLOCK_SIZE);
    if (!buffer || !decrypted_buffer) {
        printf("Error allocating memory.\n");
        fclose(fin);
        fclose(fout);
        mbedtls_aes_free(&aes);
        free(buffer);
        free(decrypted_buffer);
        return -1;
    }

    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, BUFFER_SIZE, fin)) > 0) {
        mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, bytes_read, iv, buffer, decrypted_buffer);
        
        // Remove padding from the final block
        size_t padding = decrypted_buffer[bytes_read - 1];
        if (padding > 0 && padding <= AES_BLOCK_SIZE) {
            bytes_read -= padding;
        }
        fwrite(decrypted_buffer, 1, bytes_read, fout);
    }

    free(buffer);
    free(decrypted_buffer);
    fclose(fin);
    fclose(fout);
    mbedtls_aes_free(&aes);

    printf("File decrypted successfully!\n");
    return 0;
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
