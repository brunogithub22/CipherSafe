#include "api_email.c"
#define SHA256_BIN_LEN   32
#define SHA256_HEX_LEN  (2*SHA256_BIN_LEN + 1)


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

typedef struct { 
    char *key; 
    char *value; 
} KV;

static KV* extract_form_values_generic(const cJSON *json, int *num_items, int expected_size) {
    KV *arr = malloc(expected_size * sizeof *arr);
    if (!arr) {
        *num_items = 0;
        return NULL;
    }

    int i = 0;
    for (cJSON *f = json->child; f && i < expected_size; f = f->next) {
        if (!cJSON_IsString(f)) {
            ESP_LOGW(TAG, "Skipping non‑string field %s", f->string);
            // cleanup di quanto già duplicato
            for (int j = 0; j < i; ++j) {
                free(arr[j].key);
                free(arr[j].value);
            }
            free(arr);
            *num_items = 0;
            return NULL;
        }
        arr[i].key   = strdup(f->string);
        arr[i].value = strdup(f->valuestring);
        ESP_LOGI(TAG, "key: %s, value: %s", f->string, f->valuestring);
        if (!arr[i].key || !arr[i].value) {
            // error on strdup → cleanup
            for (int j = 0; j <= i; ++j) {
                free(arr[j].key);
                free(arr[j].value);
            }
            free(arr);
            *num_items = 0;
            return NULL;
        }
        i++;
    }

    *num_items = i;
    return arr;
}

KV* extract_form_values_account(const cJSON *json, int *num_items, const char *type_form) {
    int expected = 0;
    if      (strcmp(type_form, "sign_in") == 0) expected = 2;
    else if (strcmp(type_form, "sign_up") == 0) expected = 5;
    else {
        *num_items = 0;
        return NULL;
    }

    return extract_form_values_generic(json, num_items, expected);
}


KV* extract_form_values_archive(const cJSON *json, int *num_items) {
    const int expected = 3;
    return extract_form_values_generic(json, num_items, expected);
}

KV* extract_form_values_file(const cJSON *json, int *num_items) {
    const int expected = 3;
    return extract_form_values_generic(json, num_items, expected);
}

KV* extract_form_values_load_file(const cJSON *json, int *num_items) {
    const int expected = 5;
    return extract_form_values_generic(json, num_items, expected);
}

void create_file_json_account(KV* array,cJSON* account,int count){
    for (int i = 0; i < count; ++i) {
        char *value = array[i].value; 
        if(strcmp(array[i].key,"password")==0){
            char* hex = digest((const char*)value);
            cJSON_AddStringToObject(account,(char*) array[i].key,(char *)hex);
            free(hex);
        }else{
            cJSON_AddStringToObject(account, array[i].key, array[i].value);
        }
        
    }
}

void create_file_json_archive(KV* array,cJSON* archive,int count,char* fat_string){
    for (int i = 0; i < count; ++i) {
        char *value = array[i].value; 
        if(strcmp(array[i].key,"password")==0){
            char* hex = digest((const char*)value);
            cJSON_AddStringToObject(archive,(char*) array[i].key,(char *)hex);
            free(hex);
        }else {
            cJSON_AddStringToObject(archive, array[i].key, array[i].value);
        }
    }
    cJSON_AddStringToObject(archive, "name_fat", fat_string);
    cJSON *file_array = cJSON_CreateArray();
    cJSON_AddItemToObject(archive,"files", file_array);
}

char* write_account_file(const char* filename,KV* array,int count){
    FILE* f  = fopen(filename,"r");
    char* res = "";
    if(f != NULL){
        struct stat st;
        cJSON *root;
        if (stat(filename, &st) == 0) {
            size_t size = st.st_size;
            char *data = malloc(size + 1);
            fread(data, 1, size, f);
            data[size] = '\0';
            fclose(f);   
            if(strcmp(data,"")!=0){
                root = cJSON_Parse(data);
                if (root) {
                    cJSON *account_array = cJSON_GetObjectItemCaseSensitive(root, "accounts");
                    if (cJSON_IsArray(account_array)){
                        int count_account = cJSON_GetArraySize(account_array);
                        bool same_username = false;
                        bool same_email = false;
                        
                        // Step A: pull your input values out
                        char *in_username = NULL, *in_email = NULL;
                        for (int i = 0; i < count; ++i) {
                            if (strcmp(array[i].key, "username")==0) in_username = strdup(array[i].value);
                            else if (strcmp(array[i].key, "email")==0) in_email = strdup(array[i].value);
                        }

                        // Step B: loop accounts once
                        for (int y = 0; y < count_account; ++y) {
                            cJSON *acct = cJSON_GetArrayItem(account_array,y);
                            cJSON *juser = cJSON_GetObjectItemCaseSensitive(acct,"username");
                            cJSON *jmail = cJSON_GetObjectItemCaseSensitive(acct,"email");
                            if (juser && strcmp(juser->valuestring,in_username)==0)
                                same_username = true;
                            if (jmail && strcmp(jmail->valuestring,in_email)==0)
                                same_email = true;
                        }
                        if(!same_email && !same_username){
                            cJSON *account = cJSON_CreateObject();
                            create_file_json_account(array,account,count);
                            cJSON_AddItemToArray(account_array, account);
                            char *out = cJSON_Print(root);
                            cJSON_Delete(root);
                            FILE* f = fopen(filename, "w");
                            if (f == NULL) {
                                ESP_LOGE(TAG, "Failed to open file for writing: %s (errno: %d)", filename, errno);
                            }else {
                                if(create_folder("/sdcard/FILE",in_username)){
                                    fwrite(out, 1, strlen(out), f);
                                    fclose(f);
                                    ESP_LOGI(TAG, "File written: %s", filename);
                                    res = "ok";
                                }
                            }
                            free(out);
                        }else{
                            if(same_email) res = "same email";
                            if(same_username) res = "same username";
                            printf("\nErrore:  dati incoerenti");
                        }
                        free(in_email);
                        free(in_username);
                    }
                }
            }
        }
    }
    return res;
}

char* check_archive(const char* filename,char* username,char* archive,char* passowrd,char* task,char* file_name,char* file_name_fat){
    FILE* f  = fopen(filename,"r");
    char* res = "";
    if(f != NULL){
        struct stat st;
        cJSON *root;
        if (stat(filename, &st) == 0) {
            size_t size = st.st_size;
            char *data = malloc(size + 1);
            fread(data, 1, size, f);
            data[size] = '\0';
            fclose(f);   
            if(strcmp(data,"")!=0){
                root = cJSON_Parse(data);
                if (root) {
                    cJSON *archive_array = cJSON_GetObjectItemCaseSensitive(root, "archives");
                    if (cJSON_IsArray(archive_array)){
                        int count_account = cJSON_GetArraySize(archive_array);
                        // Step B: loop accounts once
                        for (int y = 0; y < count_account; ++y) {
                            cJSON *acct = cJSON_GetArrayItem(archive_array,y);
                            cJSON *jauthor = cJSON_GetObjectItemCaseSensitive(acct,"author");
                            cJSON *jarchive = cJSON_GetObjectItemCaseSensitive(acct,"archive");
                            if ((jauthor && strcmp(jauthor->valuestring,username)==0)&& (jarchive && strcmp(jarchive->valuestring,archive)==0)){
                                if(strcmp(task,"check archive")==0){
                                    res = "ok";
                                }else if(strcmp(task,"upload file")==0){
                                    cJSON *files_array = cJSON_GetObjectItemCaseSensitive(acct,"files");
                                    if(cJSON_IsArray(files_array)){
                                        int count_files = cJSON_GetArraySize(files_array);
                                        if(count_files > 0 || count_files == 0){
                                            cJSON *file = cJSON_CreateObject();
                                            cJSON_AddStringToObject(file, "filename", file_name);
                                            cJSON_AddStringToObject(file, "name_fat", file_name_fat);
                                            cJSON_AddItemToArray(files_array,file);

                                            char *out = cJSON_Print(root);
                                            FILE* f = fopen(filename, "w");
                                            if (f == NULL) {
                                                ESP_LOGE(TAG, "Failed to open file for writing: %s (errno: %d)", filename, errno);
                                            }else {  
                                                fwrite(out, 1, strlen(out), f);
                                                fclose(f);
                                                ESP_LOGI(TAG, "File written: %s", filename);
                                                res = "ok";    
                                            }
                                            free(out);
                                        }
                                    }    
                                }
                            }
                        }
                        cJSON_Delete(root);
                    }
                }
            }
        }
    }
    return res;
}


char* write_archive(const char* filename,KV* array,int count){
    FILE* f  = fopen(filename,"r");
    char* res = "";
    if(f != NULL){
        struct stat st;
        cJSON *root;
        if (stat(filename, &st) == 0) {
            size_t size = st.st_size;
            char *data = malloc(size + 1);
            fread(data, 1, size, f);
            data[size] = '\0';
            fclose(f);   
            if(strcmp(data,"")!=0){
                root = cJSON_Parse(data);
                if (root) {
                    cJSON *archive_array = cJSON_GetObjectItemCaseSensitive(root, "archives");
                    if (cJSON_IsArray(archive_array)){
                        int count_archive = cJSON_GetArraySize(archive_array);
                        bool same_archive = false,same_author= false;
                        // Step A: pull your input values out
                        char *in_archive = NULL,*in_author = NULL;
                        for (int i = 0; i < count; ++i) {
                            if (strcmp(array[i].key, "archive")==0) in_archive = strdup(array[i].value);
                            if (strcmp(array[i].key, "author")==0) in_author = strdup(array[i].value);
                        }
                        

                        // Step B: loop accounts once
                        for (int y = 0; y < count_archive; ++y) {
                            cJSON *acct = cJSON_GetArrayItem(archive_array,y);
                            cJSON *jarchive = cJSON_GetObjectItemCaseSensitive(acct,"archive");
                            cJSON *jauthor = cJSON_GetObjectItemCaseSensitive(acct,"author");
                            if (jarchive && strcmp(jarchive->valuestring,in_archive)==0)
                                same_archive = true;
                            if (jauthor && strcmp(jauthor->valuestring,in_author)==0)
                                same_author= true;
                        }
                        if((same_author && !same_archive) || (!same_author && !same_author) ){
                            dynstr_t path,path_fat;
                            if (dynstr_init(&path) != 0) return "";
                            dynstr_append(&path, MOUNT_POINT"/FILE/");
                            dynstr_append(&path, in_author);
                            
                            if(create_folder(path.buf,in_archive)){
                                if (dynstr_init(&path_fat) != 0) return "";
                                dynstr_append(&path_fat, "0:/FILE/");
                                dynstr_append(&path_fat, in_author);
                                char sfn[13];
                                if(name_fat(path_fat.buf,in_archive,sfn,sizeof(sfn))){
                                    dynstr_free(&path);
                                    cJSON *account = cJSON_CreateObject();
                                    create_file_json_archive(array,account,count,sfn);
                                    cJSON_AddItemToArray(archive_array, account);
                                    char *out = cJSON_Print(root);
                                    cJSON_Delete(root);
                                    FILE* f = fopen(filename, "w");
                                    if (f == NULL) {
                                        ESP_LOGE(TAG, "Failed to open file for writing: %s (errno: %d)", filename, errno);
                                    }else{ 
                                        fwrite(out, 1, strlen(out), f);
                                        fclose(f);
                                        printf( "File written: %s", filename);
                                        res = "ok"; 
                                    }
                                    free(out);
                                    
                                }else{
                                    printf("Errore programma");
                                }
                            }
                            dynstr_free(&path);
                            dynstr_free(&path_fat);
                        }else{
                            if(same_archive) res = "same archive";
                        }
                        free(in_archive);
                        free(in_author);
                    }
                }
            }
        }
    }
    return res;
}

char* write_file(const char* filename,char* file,char* archive,char* password,char* name_file,char* username){
    char* res = "";
    
    
    return res;
}

char* check_account(const char* filename,char* username,char* passowrd){
    FILE* f  = fopen(filename,"r");
    char* res = "";
    if(f != NULL){
        struct stat st;
        cJSON *root;
        if (stat(filename, &st) == 0) {
            size_t size = st.st_size;
            char *data = malloc(size + 1);
            fread(data, 1, size, f);
            data[size] = '\0';
            fclose(f);   
            if(strcmp(data,"")!=0){
                root = cJSON_Parse(data);
                if (root) {
                    cJSON *account_array = cJSON_GetObjectItemCaseSensitive(root, "accounts");
                    if (cJSON_IsArray(account_array)){
                        int count_account = cJSON_GetArraySize(account_array);
                        // Step B: loop accounts once
                        for (int y = 0; y < count_account; ++y) {
                            cJSON *acct = cJSON_GetArrayItem(account_array,y);
                            cJSON *juser = cJSON_GetObjectItemCaseSensitive(acct,"username");
                            cJSON *jpassword = cJSON_GetObjectItemCaseSensitive(acct,"password");
                            cJSON *jmail = cJSON_GetObjectItemCaseSensitive(acct,"email");
                            if (juser && strcmp(juser->valuestring,username)==0){
                                passowrd = digest(passowrd);
                                if(jpassword && strcmp(jpassword->valuestring,passowrd)==0){
                                    res = "ok";
                                }
                                free(passowrd);
                            }
                        }
                        cJSON_Delete(root);
                    }
                }
            }
        }
    }
    return res;
}


void make_log(const char *message,const char *check,const char* password, char **out_log) {
    size_t buf_size = strlen(message)  + 128;
    char *log = malloc(buf_size);
    if (!log) {
        *out_log = NULL;
        if(mounted){
            sd_exit_critical();
        }
        return;
    }

    if (strcmp(message, "ok") == 0) {
        snprintf(log, buf_size,"{\"status\":\"ok\",\"account\":\"%s\",\"password\":\"%s\"}",check,password);
    }
    else {
        log = "{\"status\":\"not ok\"}";
    }

    *out_log = log;
}


esp_err_t sign_up(const char *input,httpd_req_t *req) {
    int count = 0;
    cJSON *json = cJSON_Parse(input); 
    if (!json) {
        const char *err = cJSON_GetErrorPtr();
        ESP_LOGE(TAG, "JSON parse error before: %s", err ? err : "unknown");
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }   
    KV *array = extract_form_values_account(json, &count, "sign_up");
    cJSON_Delete(json);
    if (!array) {
        // extraction failed
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    sd_enter_critical();
    char *email = NULL,*username = NULL,*password = NULL;
    char* message = write_account_file("/sdcard/CIPHER~1/ACCOUN~1.JSO", array, count);
    sd_exit_critical();

    // cleanup everything in one place
    for (int i = 0; i < count; ++i) {
        if(strcmp(array[i].key,"email")==0){
            email = strdup(array[i].value);
        }
        if(strcmp(array[i].key,"username")==0){
            username = strdup(array[i].value);
        }
        if(strcmp(array[i].key,"password")==0){
            password = strdup(array[i].value);
        }
        free(array[i].key);
        free(array[i].value);
    }
    free(array);
    if (!username) {
        ESP_LOGE(TAG, "username missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }
    if (!password) {
        ESP_LOGE(TAG, "password missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }
    if (!email) {
        ESP_LOGE(TAG, "email missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    char *log;

    make_log(message,username,password, &log);
    
    free(email);
    free(username);
    free(password);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, (const char*) log, HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}

esp_err_t sign_in(const char *input, httpd_req_t *req)
{
    int count = 0;
    cJSON *json = cJSON_Parse(input);
    if (!json) {
        const char *err = cJSON_GetErrorPtr();
        ESP_LOGE(TAG, "JSON parse error before: %s", err ? err : "unknown");
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    KV *array_account = extract_form_values_account(json, &count, "sign_in");
    cJSON_Delete(json);
    if (!array_account) {
        ESP_LOGE(TAG, "extract_form_values_account failed");
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    // Prendiamo username (e potremmo prendere anche altri campi)
    char *username = NULL,*password = NULL;
    for (int i = 0; i < count; i++) {
        if (strcmp(array_account[i].key, "username") == 0) {
            username = strdup(array_account[i].value);
        }
        if(strcmp(array_account[i].key, "password")==0){
            password = strdup(array_account[i].value);
        }

        free(array_account[i].key);
        free(array_account[i].value);
    }
    free(array_account);

    if (!username) {
        ESP_LOGE(TAG, "username missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }
    if (!password) {
        ESP_LOGE(TAG, "password missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    sd_enter_critical();
    char* message = check_account("/sdcard/CIPHER~1/ACCOUN~1.JSO", username,password);
    printf("\nMessaggio account: %s",message);
    char* log = "";
    sd_exit_critical();

    make_log(message,username,password, &log);

    free(username);
    free(password);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, (const char*) log, HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}

esp_err_t new_archive(const char *input, httpd_req_t *req){
    int count = 0;
    cJSON *json = cJSON_Parse(input);
    if (!json) {
        const char *err = cJSON_GetErrorPtr();
        ESP_LOGE(TAG, "JSON parse error before: %s", err ? err : "unknown");
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    KV *array_archive = extract_form_values_archive(json, &count);
    cJSON_Delete(json);
    if (!array_archive) {
        ESP_LOGE(TAG, "extract_form_values_account failed");
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    sd_enter_critical();
    char *archive = NULL, *password = NULL;
    char* message = write_archive("/sdcard/CIPHER~1/FILE~1.JSO", array_archive, count);
    sd_exit_critical();

    // cleanup everything in one place
    for (int i = 0; i < count; ++i) {
        if (strcmp(array_archive[i].key, "archive") == 0) {
            archive = strdup(array_archive[i].value);
        }
        if(strcmp(array_archive[i].key, "password")==0){
            password = strdup(array_archive[i].value);
        }
        free(array_archive[i].key);
        free(array_archive[i].value);
    }
    free(array_archive);

    if (!archive) {
        ESP_LOGE(TAG, "username missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }
    if (!password) {
        ESP_LOGE(TAG, "password missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }
    
    char* log = "";

    make_log(message,archive,password, &log);

    free(archive);
    free(password);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, (const char*) log, HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}

esp_err_t load_file(const char *input, httpd_req_t *req){
    int count = 0;
    cJSON *json = cJSON_Parse(input);
    if (!json) {
        const char *err = cJSON_GetErrorPtr();
        ESP_LOGE(TAG, "JSON parse error before: %s", err ? err : "unknown");
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    KV *array_account = extract_form_values_file(json, &count);
    cJSON_Delete(json);
    if (!array_account) {
        ESP_LOGE(TAG, "extract_form_values_account failed");
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    // Prendiamo username (e potremmo prendere anche altri campi)
    char *username = NULL,*password = NULL,*archive = NULL;
    for (int i = 0; i < count; i++) {
        if (strcmp(array_account[i].key, "author") == 0) {
            username = strdup(array_account[i].value);
        }
        if(strcmp(array_account[i].key, "password")==0){
            password = strdup(array_account[i].value);
        }
        if(strcmp(array_account[i].key, "archive")==0){
            archive = strdup(array_account[i].value);
        }
        free(array_account[i].key);
        free(array_account[i].value);
    }
    free(array_account);

    if (!username) {
        ESP_LOGE(TAG, "username missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }
    if (!password) {
        ESP_LOGE(TAG, "password missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }
    if (!archive) {
        ESP_LOGE(TAG, "archive missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    sd_enter_critical();
    char* log = "";
    char* message = check_archive("/sdcard/CIPHER~1/FILE~1.JSO", username,archive,password,"check archive","","");
    sd_exit_critical();

    make_log(message, archive,password, &log);

    free(username);
    free(password);
    free(archive);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, (const char*) log, HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}



esp_err_t upload_chunk( httpd_req_t *req){
    char uploadId[33], idx_s[16], tot_s[16];
    if (httpd_req_get_hdr_value_str(req, "X-Upload-Id", uploadId, sizeof(uploadId)) != ESP_OK ||
        httpd_req_get_hdr_value_str(req, "X-Chunk-Index", idx_s, sizeof(idx_s)) != ESP_OK ||
        httpd_req_get_hdr_value_str(req, "X-Total-Chunks", tot_s, sizeof(tot_s)) != ESP_OK) {
        ESP_LOGE(TAG, "Header mancante");
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Header mancante");
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    int chunkIndex = strtol(idx_s, NULL, 10);
    int totalChunks = strtol(tot_s, NULL, 10);

    // Ricerca dell'uploadId nella upload_table
    upload_meta_t *meta = NULL;
    for (int i = 0; i < MAX_UPLOADS; i++) {
        if (strcmp(upload_table[i].uploadId, uploadId) == 0) {
            meta = &upload_table[i];
            break;
        }
    }

    if (!meta) {
        ESP_LOGE(TAG, "uploadId non valido: %s", uploadId);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "uploadId non valido");
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    sd_enter_critical();
    dynstr_t path,path_encrypt,path_fat,name_encrypt;
    if (dynstr_init(&path) != 0){
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    dynstr_append(&path, MOUNT_POINT"/FILE/");
    dynstr_append(&path, meta->author);
    dynstr_append(&path, "/");
    dynstr_append(&path, meta->archive);
    dynstr_append(&path, "/");
    dynstr_append(&path, meta->filename);

    printf("Path: %s\n", path.buf);
    
    FILE *f = fopen(path.buf, "ab");
    if (!f) {
        ESP_LOGE(TAG, "Errore apertura file: %s", path.buf);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Errore apertura file");
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    // Scrittura dei dati ricevuti
    char buf[CHUNK_BUF_SIZE];
    int rlen;
    while ((rlen = httpd_req_recv(req, buf, sizeof(buf))) > 0) {
        // Log memoria prima di scrivere
        size_t heap_before = esp_get_free_heap_size();
        ESP_LOGI(TAG, "Heap prima del fwrite: %u bytes liberi", heap_before);

        fwrite(buf, 1, rlen, f);

        // Log memoria dopo scrivere
        size_t heap_after = esp_get_free_heap_size();
        ESP_LOGI(TAG, "Heap dopo il fwrite: %u bytes liberi", heap_after);
    }
    fclose(f);

    char *log,*res = "";

    // Se è l'ultimo chunk, libera lo slot nella upload_table
    if (chunkIndex + 1 == meta->totalChunks) {
        if (dynstr_init(&path_encrypt) != 0){
            if(mounted){
                sd_exit_critical();
            }
            return ESP_FAIL;
        }
        dynstr_append(&path_encrypt,path.buf);
        dynstr_append(&path_encrypt,".aes");
        if(encrypt_file(path.buf,path_encrypt.buf,(unsigned char*)meta->password)==0){
            res = "ok";
            unlink(path.buf);
        }
        if(strcmp(res,"ok")==0){
            res = "";
            if (dynstr_init(&path_fat) != 0){
                if(mounted){
                   sd_exit_critical();
                }
                return ESP_FAIL;
            }

            dynstr_append(&path_fat, "0:/FILE/");
            dynstr_append(&path_fat, meta->author);
            dynstr_append(&path_fat, "/");
            dynstr_append(&path_fat, meta->archive);
            dynstr_append(&path_fat, "/");
            dynstr_append(&path_fat, meta->filename);
            dynstr_append(&path_fat,".aes");
            char file_name_encrypt_fat[13];
    
            if (dynstr_init(&name_encrypt) != 0){
                if(mounted){
                   sd_exit_critical();
                }
                return ESP_FAIL;
            }
            dynstr_append(&name_encrypt,meta->filename);
            dynstr_append(&name_encrypt,".aes");
            if(name_fat_file(path_fat.buf,name_encrypt.buf,file_name_encrypt_fat,sizeof(file_name_encrypt_fat))){
                res = check_archive("/sdcard/CIPHER~1/FILE~1.JSO", meta->author,meta->archive,meta->password,"upload file",meta->filename,file_name_encrypt_fat);
                if(strcmp(res,"ok")==0){
                    printf("\n File json aggiornato \n");
                }else{
                    printf("\n File json non aggiornato \n");
                }
            }else{
                printf("\nFile name fat non ok \n");
            }
            dynstr_free(&path_fat);
            dynstr_free(&name_encrypt);
                
        }else{
            printf("\n Errore con la creazione del file criptato \n");
        }
        dynstr_free(&path_encrypt);
        make_log(res,meta->filename,meta->password, &log);
        *meta = (upload_meta_t){0};
        ESP_LOGI(TAG, "Upload completato: %s", path.buf);
    }
    dynstr_free(&path);
    sd_exit_critical();

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, (const char*) log, HTTPD_RESP_USE_STRLEN);
    return ESP_OK;
}

esp_err_t upload_start( httpd_req_t *req){
    // Lettura completa del body JSON
    size_t to_read = req->content_len;
    char *buf = malloc(to_read + 1);
    if (!buf) return ESP_ERR_NO_MEM;
    size_t read = 0;
    while (read < to_read) {
        int r = httpd_req_recv(req, buf + read, to_read - read);
        if (r <= 0) break;
        read += r;
    }
    buf[read] = '\0';

    // Parsing JSON
    cJSON *json = cJSON_Parse(buf);
    free(buf);
    if (!json) {
        ESP_LOGE(TAG, "JSON parse failed");
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    const cJSON *j_fn = cJSON_GetObjectItem(json, "filename");
    const cJSON *j_pw = cJSON_GetObjectItem(json, "password");
    const cJSON *j_ar = cJSON_GetObjectItem(json, "archive");
    const cJSON *j_au = cJSON_GetObjectItem(json, "author");
    const cJSON *j_tc = cJSON_GetObjectItem(json, "totalChunks");
    if (!j_fn || !j_pw || !j_ar || !j_au || !j_tc ||
        !cJSON_IsString(j_fn) || !cJSON_IsString(j_pw) ||
        !cJSON_IsString(j_ar) || !cJSON_IsString(j_au) ||
        !cJSON_IsNumber(j_tc)) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing fields");
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    // Genera uploadId
    char uploadId[33];
    generate_random_id(uploadId);

    // Trova slot libero
    bool slot_found = false;
    for (int i = 0; i < MAX_UPLOADS; i++) {
        if (upload_table[i].uploadId[0] == '\0') {
            strcpy(upload_table[i].uploadId, uploadId);
            strncpy(upload_table[i].filename, j_fn->valuestring, sizeof(upload_table[i].filename)-1);
            strncpy(upload_table[i].password, j_pw->valuestring, sizeof(upload_table[i].password)-1);
            strncpy(upload_table[i].archive,  j_ar->valuestring, sizeof(upload_table[i].archive)-1);
            strncpy(upload_table[i].author,   j_au->valuestring, sizeof(upload_table[i].author)-1);
            upload_table[i].totalChunks = j_tc->valueint;
            slot_found = true;
            break;
        }
    }
    cJSON_Delete(json);

    if (!slot_found) {
        if(mounted){
            sd_exit_critical();
        }
        return ESP_FAIL;
    }

    // Risposta JSON con uploadId
    char resp[64];
    snprintf(resp, sizeof(resp), "{\"uploadId\":\"%s\"}", uploadId);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, resp);
    return ESP_OK;
}