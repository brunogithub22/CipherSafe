#include "api_email.c"


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

KV* extract_form_values_delete_archive(const cJSON *json, int *num_items) {
    const int expected = 2;
    return extract_form_values_generic(json, num_items, expected);
}

KV* extract_form_values_delete_account(const cJSON *json, int *num_items) {
    const int expected = 1;
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
                free(data);
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
                        if(!same_email || !same_username){
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

char* check_archive(const char* filename,char* username,char* archive,char* password,char* task,char* file_name){
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
                free(data);
                if (root) {
                    cJSON *archive_array = cJSON_GetObjectItemCaseSensitive(root, "archives");
                    if (cJSON_IsArray(archive_array)){
                        int count_account = cJSON_GetArraySize(archive_array);
                        // Step B: loop accounts once
                        for (int y = 0; y < count_account; ++y) {
                            cJSON *acct = cJSON_GetArrayItem(archive_array,y);
                            cJSON *jauthor = cJSON_GetObjectItemCaseSensitive(acct,"author");
                            cJSON *jpassword = cJSON_GetObjectItemCaseSensitive(acct,"password");
                            cJSON *jarchive = cJSON_GetObjectItemCaseSensitive(acct,"archive");
                            if ((jauthor && strcmp(jauthor->valuestring,username)==0)&& (jarchive && strcmp(jarchive->valuestring,archive)==0)){
                                if(strcmp(task,"check archive")==0){
                                    char* hex = digest((const char*)password);
                                    if(strcmp(hex,jpassword->valuestring)==0){
                                        res = "ok";
                                    }else{
                                        res = "password not ok";
                                    }
                                    free(hex);
                                }else if(strcmp(task,"upload file")==0){
                                    cJSON *files_array = cJSON_GetObjectItemCaseSensitive(acct,"files");
                                    if(cJSON_IsArray(files_array)){
                                        int count_files = cJSON_GetArraySize(files_array);
                                        if(count_files > 0 || count_files == 0){
                                            cJSON *file = cJSON_CreateObject();
                                            cJSON_AddStringToObject(file, "filename", file_name);
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

char* delete_json_file(const char* filename,char* username,char* archive,char* file_name){
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
                free(data);
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
                                cJSON *files_array = cJSON_GetObjectItemCaseSensitive(acct,"files");
                                if(cJSON_IsArray(files_array)){
                                    int count_files = cJSON_GetArraySize(files_array);
                                    bool delete_file = false;
                                    if(count_files > 0 || count_files == 0){
                                        for (int i = 0; i < cJSON_GetArraySize(files_array); i++) {
                                            cJSON *file_obj = cJSON_GetArrayItem(files_array, i);
                                            cJSON *jfn = cJSON_GetObjectItemCaseSensitive(file_obj, "filename");
                                            if (jfn && strcmp(jfn->valuestring, file_name) == 0) {
                                                cJSON_DeleteItemFromArray(files_array, i);
                                                delete_file = true;
                                                i--;  // ricontrolla la nuova elemento in posizione i
                                            }
                                        }
                                        char *out = cJSON_Print(root);
                                        FILE* f = fopen(filename, "w");
                                        if (f == NULL) {
                                            ESP_LOGE(TAG, "Failed to open file for writing: %s (errno: %d)", filename, errno);
                                        }else {  
                                            fwrite(out, 1, strlen(out), f);
                                            fclose(f);
                                            ESP_LOGI(TAG, "File written: %s", filename);
                                            if(delete_file){
                                                res = "ok";
                                            }    
                                        }
                                         free(out);
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

char* delete_json_archive(const char* filename,char* archive, char* username){
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
                free(data);
                if (root) {
                    cJSON *archive_array = cJSON_GetObjectItemCaseSensitive(root, "archives");
                    if (cJSON_IsArray(archive_array)){
                        bool found = false;
                        int count_account = cJSON_GetArraySize(archive_array);
                        // Step B: loop accounts once
                        for (int y = 0; y < count_account; ++y) {
                            cJSON *acct = cJSON_GetArrayItem(archive_array,y);
                            cJSON *jauthor = cJSON_GetObjectItemCaseSensitive(acct,"author");
                            cJSON *jarchive = cJSON_GetObjectItemCaseSensitive(acct,"archive");
                            if(strcmp(username,jauthor->valuestring)==0 && strcmp(archive,jarchive->valuestring)==0){
                                cJSON_DeleteItemFromArray(archive_array, y);
                                found = true;
                            }   
                        }
                        if(found){
                            char *out = cJSON_Print(root);
                            cJSON_Delete(root);
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
    }
    return res;
}

char* delete_json_account(const char* filename, char* account){
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
                free(data);
                if (root) {
                    cJSON *account_array = cJSON_GetObjectItemCaseSensitive(root, "accounts");
                    if (cJSON_IsArray(account_array)){
                        bool found = false;
                        int count_account = cJSON_GetArraySize(account_array);
                        // Step B: loop accounts once
                        for (int y = 0; y < count_account; ++y) {
                            cJSON *acct = cJSON_GetArrayItem(account_array,y);
                            cJSON *jauthor = cJSON_GetObjectItemCaseSensitive(acct,"username");
                            if(strcmp(account,jauthor->valuestring)==0){
                                cJSON_DeleteItemFromArray(account_array, y);
                                found = true;
                            }   
                        }
                        if(found){
                            char *out = cJSON_Print(root);
                            cJSON_Delete(root);
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
                free(data);
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
                        if((same_author && !same_archive) || (!same_author && !same_archive) || (!same_author && same_archive) ){
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
                free(data);
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

esp_err_t sign_up(const char *input,httpd_req_t *req) {
    int count = 0;
    cJSON *json = cJSON_Parse(input); 
    if (!json) {
        const char *err = cJSON_GetErrorPtr();
        ESP_LOGE(TAG, "JSON parse error before: %s", err ? err : "unknown");
        
        return ESP_FAIL;
    }   
    KV *array = extract_form_values_account(json, &count, "sign_up");
    cJSON_Delete(json);
    if (!array) {
        return ESP_FAIL;
    }

    char* message = write_account_file("/sdcard/CIPHER~1/ACCOUN~1.JSO", array, count);

    // cleanup everything in one place
    for (int i = 0; i < count; ++i) {
        free(array[i].key);
        free(array[i].value);
    }
    free(array);
    
    char *log = "{\"status\":\"not ok\"}";
    if(strcmp(message,"ok")==0){
        log = "{\"status\":\"ok\"}";
    }

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
        
        return ESP_FAIL;
    }

    KV *array_account = extract_form_values_account(json, &count, "sign_in");
    cJSON_Delete(json);
    if (!array_account) {
        ESP_LOGE(TAG, "extract_form_values_account failed");
        
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
        
        return ESP_FAIL;
    }
    if (!password) {
        ESP_LOGE(TAG, "password missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        
        return ESP_FAIL;
    }

    char* message = check_account("/sdcard/CIPHER~1/ACCOUN~1.JSO", username,password);
    printf("\nMessaggio account: %s\n",message);
    
    char *log = "{\"status\":\"not ok\"}";
    if(strcmp(message,"ok")==0){
        log = "{\"status\":\"ok\"}";
    }

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
        
        return ESP_FAIL;
    }

    KV *array_archive = extract_form_values_archive(json, &count);
    cJSON_Delete(json);
    if (!array_archive) {
        ESP_LOGE(TAG, "extract_form_values_account failed");
        
        return ESP_FAIL;
    }

    char *archive = NULL, *password = NULL;
    char* message = write_archive("/sdcard/CIPHER~1/FILE~1.JSO", array_archive, count);
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
        
        return ESP_FAIL;
    }
    if (!password) {
        ESP_LOGE(TAG, "password missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        
        return ESP_FAIL;
    }
    
    char *log = "{\"status\":\"not ok\"}";
    if(strcmp(message,"ok")==0){
        log = "{\"status\":\"ok\"}";
    }

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
        
        return ESP_FAIL;
    }

    KV *array_account = extract_form_values_file(json, &count);
    cJSON_Delete(json);
    if (!array_account) {
        ESP_LOGE(TAG, "extract_form_values_account failed");
        
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
        
        return ESP_FAIL;
    }
    if (!password) {
        ESP_LOGE(TAG, "password missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"password missing\"}",HTTPD_RESP_USE_STRLEN);
        
        return ESP_FAIL;
    }
    if (!archive) {
        ESP_LOGE(TAG, "archive missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"archive missing\"}",HTTPD_RESP_USE_STRLEN);
        
        return ESP_FAIL;
    }

    char* message = check_archive("/sdcard/CIPHER~1/FILE~1.JSO", username,archive,password,"check archive","");

    char *log = "{\"status\":\"not ok\"}";
    if(strcmp(message,"ok")==0){
        log = "{\"status\":\"ok\"}";
    }

    free(username);
    free(password);
    free(archive);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, (const char*) log, HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}


// ============================
// === upload_start_handler ===
// ============================
esp_err_t upload_start_handler(httpd_req_t *req) {
    size_t to_read = req->content_len;
    ESP_LOGI(TAG, "📤 Inizio upload: payload JSON = %u byte", (unsigned)to_read);

    char *buf = malloc(to_read + 1);
    if (!buf) return ESP_ERR_NO_MEM;

    size_t received = 0;
    while (received < to_read) {
        int ret = httpd_req_recv(req, buf + received, to_read - received);
        if (ret <= 0) {
            free(buf);
            ESP_LOGE(TAG, "Errore nella ricezione JSON di start_upload");
            return ESP_FAIL;
        }
        received += ret;
        ESP_LOGI(TAG, "📥 Ricevuti JSON start: %u/%u byte", (unsigned)received, (unsigned)to_read);
    }
    buf[received] = '\0';

    cJSON *json = cJSON_Parse(buf);
    free(buf);
    if (!json) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    // Estrai metadati
    const cJSON *j_fn = cJSON_GetObjectItem(json, "filename");
    const cJSON *j_pw = cJSON_GetObjectItem(json, "password");
    const cJSON *j_ar = cJSON_GetObjectItem(json, "archive");
    const cJSON *j_au = cJSON_GetObjectItem(json, "author");
    const cJSON *j_tc = cJSON_GetObjectItem(json, "totalChunks");
    if (!cJSON_IsString(j_fn) || !cJSON_IsString(j_pw) ||
        !cJSON_IsString(j_ar) || !cJSON_IsString(j_au) ||
        !cJSON_IsNumber(j_tc)) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing fields");
        return ESP_FAIL;
    }

    // Genera uploadId e registra slot
    char uploadId[33];
    generate_random_id(uploadId);
    bool slot_found = false;
    for (int i = 0; i < MAX_UPLOADS; i++) {
        if (upload_table[i].uploadId[0] == '\0') {
            strcpy(upload_table[i].uploadId, uploadId);
            strncpy(upload_table[i].filename, j_fn->valuestring, sizeof(upload_table[i].filename)-1);
            strncpy(upload_table[i].password, j_pw->valuestring, sizeof(upload_table[i].password)-1);
            strncpy(upload_table[i].archive,  j_ar->valuestring, sizeof(upload_table[i].archive)-1);
            strncpy(upload_table[i].author,   j_au->valuestring, sizeof(upload_table[i].author)-1);
            upload_table[i].totalChunks = j_tc->valueint;
            upload_table[i].done        = false;
            slot_found = true;
            upload_table[i].cumulative_bytes = 0; 
            break;
        }
    }
    cJSON_Delete(json);

    if (!slot_found) {
        ESP_LOGE(TAG, "Nessuno slot libero per upload");
        return ESP_FAIL;
    }

    // Risposta
    char resp[64];
    snprintf(resp, sizeof(resp), "{\"uploadId\":\"%s\"}", uploadId);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, resp);
    ESP_LOGI(TAG, "📶 Sessione upload avviata: uploadId=%s", uploadId);
    return ESP_OK;
}

void replace_spaces(char *s, char ch) {
    for (size_t i = 0; i < strlen(s); ++i) {
        if (s[i] == ' ') {
            s[i] = ch;
        }
    }
}

// =================================
// === upload_chunk_handler    ====
// =================================
esp_err_t upload_chunk_handler(httpd_req_t *req) {
    char uploadId[33], idx_s[16], tot_s[16];
    if (httpd_req_get_hdr_value_str(req, "X-Upload-Id",    uploadId, sizeof(uploadId)) != ESP_OK ||
        httpd_req_get_hdr_value_str(req, "X-Chunk-Index",  idx_s,     sizeof(idx_s))  != ESP_OK ||
        httpd_req_get_hdr_value_str(req, "X-Total-Chunks", tot_s,     sizeof(tot_s))  != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing headers");
        return ESP_FAIL;
    }

    int chunkIndex  = atoi(idx_s);
    int totalChunks = atoi(tot_s);

    // Trova metadati
    upload_meta_t *meta = NULL;
    int slot = -1;
    for (int i = 0; i < MAX_UPLOADS; i++) {
        if (strcmp(upload_table[i].uploadId, uploadId) == 0) {
            meta = &upload_table[i];
            slot = i;
            break;
        }
    }
    if (!meta) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid uploadId");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "📤 Ricevo chunk %d/%d per uploadId=%s", chunkIndex+1, totalChunks, uploadId);

    replace_spaces(meta->filename,'_');

    dynstr_t path; dynstr_init(&path);
    dynstr_append(&path, MOUNT_POINT "/FILE/");
    dynstr_append(&path, meta->author);
    dynstr_append(&path, "/");
    dynstr_append(&path, meta->archive);
    dynstr_append(&path, "/");
    dynstr_append(&path, meta->filename);

    FILE *f = fopen(path.buf, "ab");
    if (!f) {
        ESP_LOGE(TAG, "Errore apertura file: %s", path.buf);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "File open failed");
        dynstr_free(&path);
        return ESP_FAIL;
    }

    char buf[CHUNK_BUF_SIZE];
    int  rlen;
    while ((rlen = httpd_req_recv(req, buf, sizeof(buf))) > 0) {
        fwrite(buf, 1, rlen, f);
        meta->cumulative_bytes += rlen;
        ESP_LOGI(TAG, "📝 Cumulativo: %u byte ricevuti finora", (unsigned)meta->cumulative_bytes);
    }
    fclose(f);

    // Se ultimo chunk, cifro, segno done e resetto contatore
    if (chunkIndex + 1 == totalChunks) {
        ESP_LOGI(TAG, "✅ Upload completato: totali %u byte", (unsigned)meta->cumulative_bytes);

        dynstr_t path_enc; 
        dynstr_init(&path_enc);
        dynstr_append(&path_enc, path.buf);
        dynstr_append(&path_enc, ".aes");

        unsigned char key_hash256[32];
        create_key((unsigned char*)meta->password, key_hash256);
        if (encrypt_file(path.buf, path_enc.buf, key_hash256) == 0) {
            upload_table[slot].done = true;
            char* res = check_archive("/sdcard/CIPHER~1/FILE~1.JSO", meta->author,meta->archive,"","upload file",meta->filename);
            if(strcmp(res,"ok")==0){
                printf("\n JSON aggiornato \n");
            }
            unlink(path.buf);
        } else {
            ESP_LOGE(TAG, "Errore cifratura finale");
        }
        dynstr_free(&path_enc);
    }

    dynstr_free(&path);
   

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"chunk ok\"}");
    return ESP_OK;
}

// ====================================
// === upload_finalize_handler     ====
// ====================================
esp_err_t upload_finalize_handler(httpd_req_t *req) {
    char uploadId[33];
    if (httpd_req_get_hdr_value_str(req, "X-Upload-Id", uploadId, sizeof(uploadId)) != ESP_OK) {
        return httpd_resp_send_404(req);
    }
    for (int i = 0; i < MAX_UPLOADS; i++) {
        if (strcmp(upload_table[i].uploadId, uploadId) == 0) {
            const char *resp = upload_table[i].done
                ? "{\"status\":\"done\"}"
                : "{\"status\":\"pending\"}";
            httpd_resp_set_type(req, "application/json");
            httpd_resp_sendstr(req, resp);
            ESP_LOGI(TAG, "Polling finalize: uploadId=%s status=%s",
                     uploadId,
                     upload_table[i].done ? "done" : "pending");
            return ESP_OK;
        }
    }
    return httpd_resp_send_404(req);
}
// ============================
// ===   download_file    ====
// ============================
esp_err_t download_handler(httpd_req_t *req)
{
    // --- 1) Ricezione e parsing JSON ---
    size_t to_read = req->content_len;
    ESP_LOGI(TAG, "📥 Inizio download JSON %u byte", (unsigned)to_read);

    char *buf = malloc(to_read + 1);
    if (!buf) return ESP_ERR_NO_MEM;

    size_t rec = 0;
    while (rec < to_read) {
        int r = httpd_req_recv(req, buf + rec, to_read - rec);
        if (r <= 0) {
            free(buf);
            ESP_LOGE(TAG, "Errore ricezione JSON");
            return ESP_FAIL;
        }
        rec += r;
    }
    buf[rec] = '\0';

    cJSON *json = cJSON_Parse(buf);
    free(buf);
    if (!json) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    const cJSON *j_fn = cJSON_GetObjectItem(json, "filename");
    const cJSON *j_pw = cJSON_GetObjectItem(json, "password");
    const cJSON *j_ar = cJSON_GetObjectItem(json, "archive");
    const cJSON *j_au = cJSON_GetObjectItem(json, "author");
    if (!cJSON_IsString(j_fn) || !cJSON_IsString(j_pw) ||
        !cJSON_IsString(j_ar) || !cJSON_IsString(j_au)) {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing fields");
        return ESP_FAIL;
    }
    char *filename = strdup(j_fn->valuestring);
    char *password = strdup(j_pw->valuestring);
    char *archive  = strdup(j_ar->valuestring);
    char *author   = strdup(j_au->valuestring);
    cJSON_Delete(json);

    // --- 2) Deriva chiave ---
    unsigned char key_hash[32];
    create_key((unsigned char*)password, key_hash);

    // --- 3) Percorsi file cifrato e file temporaneo decrypted ---
    dynstr_t path_enc; dynstr_init(&path_enc);
    dynstr_append(&path_enc, MOUNT_POINT "/FILE/");
    dynstr_append(&path_enc, author);
    dynstr_append(&path_enc, "/");
    dynstr_append(&path_enc, archive);
    dynstr_append(&path_enc, "/");
    dynstr_append(&path_enc, filename);
    dynstr_append(&path_enc, ".aes");

    dynstr_t path; dynstr_init(&path);
    dynstr_append(&path, MOUNT_POINT "/FILE/");
    dynstr_append(&path, author);
    dynstr_append(&path, "/");
    dynstr_append(&path, archive);
    dynstr_append(&path, "/");
    dynstr_append(&path, filename);

      // 2) Decrypt file su disco
    int dec_ret = decrypt_file(path_enc.buf, path.buf, key_hash);
    if (dec_ret != 0) {
        ESP_LOGE(TAG, "Errore in decrypt_file (%d)", dec_ret);
        return ESP_FAIL;
    }

    struct stat st;
    if (stat(path_enc.buf, &st) != 0 || !S_ISREG(st.st_mode)) {
        ESP_LOGE(TAG, "File decriptato non trovato: %s", path_enc.buf);
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found");
        return ESP_FAIL;
    }
    size_t total = st.st_size;
    ESP_LOGI(TAG, "➡️  Avvio streaming di %u byte", (unsigned)total);

    // 3) Apri file decriptato per lo streaming
    FILE *fdec = fopen(path.buf, "rb");
    if (!fdec) {
        ESP_LOGE(TAG, "Impossibile aprire %s", path.buf);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Open failed");
        return ESP_FAIL;
    }

    // Imposta header HTTP per attachment
    httpd_resp_set_type(req, "application/octet-stream");
    char cd[128];
    snprintf(cd, sizeof(cd),
             "attachment; filename=\"%s\"", filename);
    httpd_resp_set_hdr(req, "Content-Disposition", cd);

    // Invia a chunk
    const size_t CHUNK = CHUNK_BUF_SIZE;
    uint8_t chunk[CHUNK];
    size_t sent = 0,rlen;
    while ((rlen = fread(chunk, 1, CHUNK, fdec)) > 0) {
        if (httpd_resp_send_chunk(req, (const char*)chunk, rlen) != ESP_OK) {
            ESP_LOGE(TAG, "Errore invio chunk a %u/%u byte",(unsigned)sent, (unsigned)total);
            break;
        }
        sent += rlen;
        ESP_LOGI(TAG, "⬇️  Scaricati %u/%u byte",(unsigned)sent, (unsigned)total);
    }
    httpd_resp_send_chunk(req, NULL, 0);
    fclose(fdec);
    dynstr_free(&path_enc);
    unlink(path.buf);
    dynstr_free(&path);
    free(filename);
    free(password);
    free(archive);
    free(author);

    return ESP_OK;
}

static esp_err_t delete_handler(httpd_req_t *req)
{
    // 1) Leggi tutto il body JSON
    size_t len = req->content_len;
    char *buf = malloc(len + 1);
    if (!buf) return ESP_ERR_NO_MEM;
    if (httpd_req_recv(req, buf, len) != (int)len) {
        free(buf);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid body");
        return ESP_FAIL;
    }
    buf[len] = '\0';

    // 2) Parse JSON
    cJSON *json = cJSON_Parse(buf);
    free(buf);
    if (!json) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Malformed JSON");
        return ESP_FAIL;
    }

    const cJSON *j_fn = cJSON_GetObjectItemCaseSensitive(json, "filename");
    const cJSON *j_pw = cJSON_GetObjectItemCaseSensitive(json, "password");
    const cJSON *j_ar = cJSON_GetObjectItemCaseSensitive(json, "archive");
    const cJSON *j_au = cJSON_GetObjectItemCaseSensitive(json, "author");
    if (!cJSON_IsString(j_fn) || !cJSON_IsString(j_pw) ||
        !cJSON_IsString(j_ar) || !cJSON_IsString(j_au))
    {
        cJSON_Delete(json);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing fields");
        return ESP_FAIL;
    }

    char *filename = strdup(j_fn->valuestring);
    char *password = strdup(j_pw->valuestring);
    char *archive  = strdup(j_ar->valuestring);
    char *author   = strdup(j_au->valuestring);
    cJSON_Delete(json);

    // 4) Costruisci il path del file cifrato .aes
    dynstr_t path; dynstr_init(&path);
    dynstr_append(&path, MOUNT_POINT "/FILE/");
    dynstr_append(&path, author);
    dynstr_append(&path, "/");
    dynstr_append(&path, archive);
    dynstr_append(&path, "/");
    dynstr_append(&path, filename);
    dynstr_append(&path, ".aes");

    // 5) Verifica esistenza
    struct stat st;
    if (stat(path.buf, &st) != 0 || !S_ISREG(st.st_mode)) {
        dynstr_free(&path);
        free(filename); free(password); free(archive); free(author);
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "File not found");
        return ESP_FAIL;
    }

    // 6) Elimina il file
    if (unlink(path.buf) != 0) {
        ESP_LOGE(TAG, "unlink failed: %s", path.buf);
        dynstr_free(&path);
        free(filename); free(password); free(archive); free(author);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Delete failed");
        return ESP_FAIL;
    }
    char* res = delete_json_file("/sdcard/CIPHER~1/FILE~1.JSO",author,archive,filename);
    if(strcmp(res,"ok")==0){
        printf("\n File tolto dal json\n ");
    }

    // 7) Cleanup e risposta OK
    dynstr_free(&path);
    free(filename); free(password); free(archive); free(author);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, "{\"status\":\"ok\"}");
    return ESP_OK;
}


int delete_folder_recursive_archive(const char *path,KV* array) {
    DIR *d = opendir(path);
    if (!d) {
        fprintf(stderr, "opendir %s failed: %s\n", path, strerror(errno));
        return -1;
    }
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        dynstr_t path_child_fat,path_name;
        dynstr_init(&path_child_fat);
        dynstr_init(&path_name);
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char* username = array[0].value;
        char* archive = array[1].value;
        char* username_fat = array[2].value;
        char* archive_fat = array[3].value;

            // Costruisci il percorso completo
        char name_fat[13];
   
        dynstr_append(&path_child_fat,"0:/FILE/");
        dynstr_append(&path_child_fat,username);
        dynstr_append(&path_child_fat,"/");
        dynstr_append(&path_child_fat,archive);
        dynstr_append(&path_child_fat,"/");
  
        if(!name_fat_file(path_child_fat.buf,entry->d_name,name_fat,sizeof(name_fat))){
            printf("\n Errore contenuto\n");
            dynstr_free(&path_child_fat);
            dynstr_free(&path_name);
            return -1;
        }

        size_t ulen_ = strlen(name_fat);
        while (ulen_ && name_fat[ulen_-1]==' ') {
            name_fat[--ulen_]='\0';
        }

        printf("\n file: %s",name_fat);
           
        dynstr_append(&path_name,MOUNT_POINT"/FILE/");
        dynstr_append(&path_name,username);
        dynstr_append(&path_name,"/");
        dynstr_append(&path_name,archive);
        dynstr_append(&path_name,"/");
        dynstr_append(&path_name,name_fat);

        struct stat st;
        if (stat(path_name.buf, &st) != 0) {
            fprintf(stderr, "stat %s failed: %s\n", path_name.buf, strerror(errno));
            closedir(d);
            dynstr_free(&path_child_fat);
            dynstr_free(&path_name);
            return -1;
        }

        if (S_ISDIR(st.st_mode)) {} 
        else {
            if (unlink(path_name.buf) != 0) {
                fprintf(stderr, "unlink %s failed: %s\n", path_name.buf, strerror(errno));
                closedir(d);
                dynstr_free(&path_child_fat);
                dynstr_free(&path_name);
                return -1;
            }
        }
        path_child_fat.len = 0;
        path_child_fat.buf[0] = '\0';
        path_name.len      = 0;
        path_name.buf[0]   = '\0';
        dynstr_free(&path_child_fat);
        dynstr_free(&path_name); 
       
    }
    closedir(d);

    // Rimuovi la directory ora vuota
    if (rmdir(path) != 0) {
        fprintf(stderr, "rmdir %s failed: %s\n", path, strerror(errno));
        return -1;
    }else{
        printf("\n Cartella %s eliminata\n",path);
        char* res = delete_json_archive("/sdcard/CIPHER~1/FILE~1.JSO",array[1].value,array[0].value);
        if(strcmp(res,"ok")==0){
           printf("\n archive json aggiornato archive\n ");
           return 0;
        }
    }
    return -1;
}

int delete_folder_recursive_account(const char *path,KV* array) {
    DIR *d = opendir(path);
    if (!d) {
        fprintf(stderr, "opendir %s failed: %s\n", path, strerror(errno));
        return -1;
    }
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        dynstr_t path_,path_fat_username;
        dynstr_init(&path_);
        dynstr_init(&path_fat_username);

        printf("username_fat = \"%s\"\n", array[1].value);

        dynstr_append(&path_fat_username,"0:/FILE/");
        dynstr_append(&path_fat_username,array[1].value); 
        dynstr_append(&path_fat_username,"/");

        char archive_fat[12] = "";
        if (!name_fat(path_fat_username.buf, entry->d_name, archive_fat, sizeof(archive_fat))) {
            printf("archive_fat = \"%s\"\n", archive_fat);
            printf("\n Errore archive\n");
            dynstr_free(&path_);
            dynstr_free(&path_fat_username);
            return -1;
        }    

        printf("archive_fat = \"%s\"\n", archive_fat);

        size_t ulen = strlen(archive_fat);
        while (ulen && archive_fat[ulen-1]==' ') {
            archive_fat[--ulen]='\0'; 
        }

        dynstr_append(&path_,MOUNT_POINT"/FILE/");
        dynstr_append(&path_,array[1].value);
        dynstr_append(&path_,"/");
        dynstr_append(&path_,archive_fat);

        printf("\n path: %s", path_.buf);

        KV *arr = malloc(4 * sizeof *arr);
        if (!arr) {
            return -1;
        }

        arr[0].key = strdup("username");
        arr[1].key = strdup("archive");
        arr[2].key = strdup("username_fat");
        arr[3].key = strdup("archive_fat");

        arr[0].value = strdup(array[0].value);
        arr[1].value = strdup(entry->d_name);
        arr[2].value = strdup(array[1].value);
        arr[3].value = strdup(archive_fat);

        struct stat st;
        if (stat(path_.buf, &st) != 0) {
            fprintf(stderr, "stat %s failed: %s\n", path_.buf, strerror(errno));
            closedir(d);
            dynstr_free(&path_);
            dynstr_free(&path_fat_username);
            return -1;
        }

        if (S_ISDIR(st.st_mode)) {
            if (delete_folder_recursive_archive(path_.buf,arr) != 0)
            {
                dynstr_free(&path_fat_username);
                dynstr_free(&path_);
                closedir(d);
                return -1;
            }
        } 
            
        for(int i=0;i<4;i++){
            free(arr[i].key);
            free(arr[i].value); 
        }
        free(arr);

        dynstr_free(&path_);
        dynstr_free(&path_fat_username);
    }
    closedir(d);

    // Rimuovi la directory ora vuota
    if (rmdir(path) != 0) {
        fprintf(stderr, "rmdir %s failed: %s\n", path, strerror(errno));
        return -1;
    }else{
        printf("\n Cartella %s eliminata\n",path);
        char* res = delete_json_account("/sdcard/CIPHER~1/ACCOUN~1.JSO",array[0].value);
        if(strcmp(res,"ok")==0){
           printf("\n archive json aggiornato archive\n ");
           return 0;
        }
    }
    return -1;
}

esp_err_t delete_archive(const char *input,httpd_req_t *req) {
    int count = 0;
    cJSON *json = cJSON_Parse(input); 
    if (!json) {
        const char *err = cJSON_GetErrorPtr();
        ESP_LOGE(TAG, "JSON parse error before: %s", err ? err : "unknown");
        
        return ESP_FAIL;
    }   
    KV *array = extract_form_values_delete_archive(json, &count);
    cJSON_Delete(json);
    if (!array) {
        return ESP_FAIL;
    }

    char *archive = NULL,*username = NULL;

    // cleanup everything in one place
    for (int i = 0; i < count; ++i) {
        if(strcmp(array[i].key,"archive")==0){
            archive = strdup(array[i].value);
        }
        if(strcmp(array[i].key,"username")==0){
            username = strdup(array[i].value);
        }
        free(array[i].key);
        free(array[i].value);
    }
    free(array);
    if (!username) {
        ESP_LOGE(TAG, "username missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }
    if (!archive) {
        ESP_LOGE(TAG, "archive missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"archive missing\"}",HTTPD_RESP_USE_STRLEN);   
        return ESP_FAIL;
    }

    dynstr_t path,path_fat_username;
    dynstr_init(&path);
    dynstr_init(&path_fat_username);

    char username_fat[12] = "";
    if (!name_fat("0:/FILE/", username, username_fat, sizeof(username_fat))) {
        printf("\n Errore username \n");
        dynstr_free(&path);
        dynstr_free(&path_fat_username);
        free(archive);
        free(username);
        httpd_resp_send(req, "{\"status\":\"error\",\"message\":\"invalid username SFN\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }

    size_t ulen_ = strlen(username_fat);
    while (ulen_ && username_fat[ulen_-1]==' ') {
        username_fat[--ulen_]='\0';
    }

    printf("username_fat = \"%s\"\n", username_fat);

    dynstr_append(&path_fat_username,"0:/FILE/");
    dynstr_append(&path_fat_username,username_fat);
    dynstr_append(&path_fat_username,"/");


    char archive_fat[12] = "";
    if (!name_fat(path_fat_username.buf, archive, archive_fat, sizeof(archive_fat))) {
        printf("archive_fat = \"%s\"\n", archive_fat);
        printf("\n Errore archive\n");
        dynstr_free(&path);
        dynstr_free(&path_fat_username);
        free(archive);
        free(username);
        httpd_resp_send(req, "{\"status\":\"error\",\"message\":\"invalid archive SFN\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }

    printf("archive_fat = \"%s\"\n", archive_fat);

    size_t ulen = strlen(archive_fat);
    while (ulen && archive_fat[ulen-1]==' ') {
        archive_fat[--ulen]='\0'; 
    }

    dynstr_append(&path,MOUNT_POINT"/FILE/");
    dynstr_append(&path,username_fat);
    dynstr_append(&path,"/");
    dynstr_append(&path,archive_fat);

    printf("\n path: %s", path.buf);

    KV *arr = malloc(4 * sizeof *arr);
    if (!arr) {
        return ESP_FAIL;
    }

    arr[0].key = strdup("username");
    arr[1].key = strdup("archive");
    arr[2].key = strdup("username_fat");
    arr[3].key = strdup("archive_fat");

    arr[0].value = strdup(username);
    arr[1].value = strdup(archive);
    arr[2].value = strdup(username_fat);
    arr[3].value = strdup(archive_fat);

    char *log = "{\"status\":\"not ok\"}";
    if(delete_folder_recursive_archive(path.buf,arr)==0){
        log = "{\"status\":\"ok\"}";
    }

    for(int i=0;i<4;i++){
        free(arr[i].key);
        free(arr[i].value);
    }
    free(arr);

    dynstr_free(&path);
    dynstr_free(&path_fat_username);
    free(archive);
    free(username);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, (const char*) log, HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}

esp_err_t delete_account(const char *input,httpd_req_t *req) {
    int count = 0;
    cJSON *json = cJSON_Parse(input); 
    if (!json) {
        const char *err = cJSON_GetErrorPtr();
        ESP_LOGE(TAG, "JSON parse error before: %s", err ? err : "unknown");
        
        return ESP_FAIL;
    }   
    KV *array = extract_form_values_delete_account(json, &count);
    cJSON_Delete(json);
    if (!array) {
        return ESP_FAIL;
    }

    char *username = NULL;

    // cleanup everything in one place
    for (int i = 0; i < count; ++i) {
        if(strcmp(array[i].key,"username")==0){
            username = strdup(array[i].value);
        }
        free(array[i].key);
        free(array[i].value);
    }
    free(array);
    if (!username) {
        ESP_LOGE(TAG, "username missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }

    dynstr_t path;
    dynstr_init(&path);

    char username_fat[12] = "";
    if (!name_fat("0:/FILE/", username, username_fat, sizeof(username_fat))) {
        printf("\n Errore username \n");
        dynstr_free(&path);
        free(username);
        httpd_resp_send(req, "{\"status\":\"error\",\"message\":\"invalid username SFN\"}", HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }

    size_t ulen_ = strlen(username_fat);
    while (ulen_ && username_fat[ulen_-1]==' ') {
        username_fat[--ulen_]='\0';
    }

    printf("username_fat = \"%s\"\n", username_fat);

    dynstr_append(&path,MOUNT_POINT"/FILE/");
    dynstr_append(&path,username_fat);
    
    printf("\n path: %s", path.buf);

    KV *arr = malloc(2 * sizeof *arr);
    if (!arr) {
        return ESP_FAIL;
    }

    arr[0].key = strdup("username");
    arr[1].key = strdup("username_fat");

    arr[0].value = strdup(username);
    arr[1].value = strdup(username_fat);

    char *log = "{\"status\":\"not ok\"}";
    if(delete_folder_recursive_account(path.buf,arr)==0){
        log = "{\"status\":\"ok\"}";
    }

    for(int i=0;i<2;i++){
        free(arr[i].key);
        free(arr[i].value);
    }
    free(arr);

    dynstr_free(&path);
    free(username);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, (const char*) log, HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}
