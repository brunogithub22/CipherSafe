#include "wifi.c"

#define TOKEN_BYTES   16
#define TOKEN_STR_LEN (TOKEN_BYTES * 2 + 1)

static const char *template_verification = 
"<!DOCTYPE html>"
"<html lang=\"it\">"
"<head>"
  "<meta charset=\"UTF-8\">"
  "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
  "<title>Conferma la tua email</title>"
"</head>"
"<body style=\"margin:0; padding:0; background-color:#f4f4f4;\">"
  "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color:#f4f4f4; padding:20px 0;\">"
    "<tr>"
      "<td align=\"center\">"
        "<!-- Contenitore principale -->"
        "<table role=\"presentation\" width=\"600\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color:#ffffff; border-radius:8px; overflow:hidden;\">"
          "<!-- Header -->"
          "<tr>"
            "<td align=\"center\" style=\"padding:30px; background-color:#007BFF;\">"
              "<h1 style=\"margin:0; font-family:Arial, sans-serif; color:#ffffff; font-size:24px;\">Email Verificata!</h1>"
            "</td>"
          "</tr>"
          "<!-- Corpo -->"
          "<tr>"
            "<td style=\"padding:30px; font-family:Arial, sans-serif; color:#333333; font-size:16px; line-height:1.5;\">"
              "<p>Ciao,</p>"
              "<p>L'email è verificata, puoi continuare adesso cliccare puoi continuare con la creazione dell'account.</p>" 
              "<p>Grazie,<br>Il team di CipherSafe</p>"
            "</td>"
          "</tr>"
          "<!-- Footer -->"
          "<tr>"
            "<td align=\"center\" style=\"padding:20px; background-color:#f4f4f4; font-family:Arial, sans-serif; font-size:12px; color:#777777;\">"
              "© 2025 CipherSafe. Tutti i diritti riservati.<br>"
            "</td>"
          "</tr>"
        "</table>"
        "<!-- /Contenitore principale -->"
      "</td>"
    "</tr>"
  "</table>"
"</body>"
"</html>";

static const char *template_code = 
"<!DOCTYPE html>"
"<html lang=\"it\">"
"<head>"
  "<meta charset=\"UTF-8\">"
  "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
  "<title>Conferma la tua email</title>"
"</head>"
"<body style=\"margin:0; padding:0; background-color:#f4f4f4;\">"
  "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color:#f4f4f4; padding:20px 0;\">"
    "<tr>"
      "<td align=\"center\">"
        "<!-- Contenitore principale -->"
        "<table role=\"presentation\" width=\"600\" cellpadding=\"0\" cellspacing=\"0\" style=\"background-color:#ffffff; border-radius:8px; overflow:hidden;\">"
          "<!-- Header -->"
          "<tr>"
            "<td align=\"center\" style=\"padding:30px; background-color:#007BFF;\">"
              "<h1 style=\"margin:0; font-family:Arial, sans-serif; color:#ffffff; font-size:24px;\">Email Verificata!</h1>"
            "</td>"
          "</tr>"
          "<!-- Corpo -->"
          "<tr>"
            "<td style=\"padding:30px; font-family:Arial, sans-serif; color:#333333; font-size:16px; line-height:1.5;\">"
              "<p>Ciao,</p>"
              "<p>Il codice è: %s</p>" 
              "<p>Grazie,<br>Il team di CipherSafe</p>"
            "</td>"
          "</tr>"
          "<!-- Footer -->"
          "<tr>"
            "<td align=\"center\" style=\"padding:20px; background-color:#f4f4f4; font-family:Arial, sans-serif; font-size:12px; color:#777777;\">"
              "© 2025 CipherSafe. Tutti i diritti riservati.<br>"
            "</td>"
          "</tr>"
        "</table>"
        "<!-- /Contenitore principale -->"
      "</td>"
    "</tr>"
  "</table>"
"</body>"
"</html>";

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

KV* extract_form_values_email(const cJSON *json, int *num_items) {
    const int expected = 4;
    return extract_form_values_generic(json, num_items, expected);
}

KV* extract_form_values_send_code(const cJSON *json, int *num_items) {
    const int expected = 1;
    return extract_form_values_generic(json, num_items, expected);
}

KV* extract_form_values_change_password(const cJSON *json, int *num_items) {
    const int expected = 3;
    return extract_form_values_generic(json, num_items, expected);
}

char* get_data(const char* filename,char* username,char* name){
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
                    cJSON *archive_array = cJSON_GetObjectItemCaseSensitive(root, "accounts");
                    if (cJSON_IsArray(archive_array)){
                        int count_account = cJSON_GetArraySize(archive_array);
                        // Step B: loop accounts once
                        for (int y = 0; y < count_account; ++y) {
                            cJSON *acct = cJSON_GetArrayItem(archive_array,y);
                            cJSON *jusername = cJSON_GetObjectItemCaseSensitive(acct, "username");
                            cJSON *jelement = cJSON_GetObjectItemCaseSensitive(acct, name);
                            if(strcmp(jusername->valuestring,username)==0){
                                res = strdup(jelement->valuestring);
                                printf("\n %s: %s \n",name,res);
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

bool change_password_json(const char* filename,char* username,char* new_password){
    bool res = false;
    FILE* f  = fopen(filename,"r");
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
                    cJSON *archive_array = cJSON_GetObjectItemCaseSensitive(root, "accounts");
                    if (cJSON_IsArray(archive_array)){
                        bool found = false;
                        int count_account = cJSON_GetArraySize(archive_array);
                        // Step B: loop accounts once
                        for (int y = 0; y < count_account; ++y) {
                            cJSON *acct = cJSON_GetArrayItem(archive_array,y);
                            cJSON *jauthor = cJSON_GetObjectItemCaseSensitive(acct,"username");
                            cJSON *jpassword = cJSON_GetObjectItemCaseSensitive(acct,"password");
                            if(strcmp(username,jauthor->valuestring)==0){
                                cJSON_DeleteItemFromObject(acct, "password"); 
                                char* hex = digest((const char*)new_password);
                                cJSON_AddStringToObject(acct,(char*)"password",(char *)hex);
                                free(hex);
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
                                res = true;            
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


// Gestione eventi HTTP
static esp_err_t http_event_handler(esp_http_client_event_t *evt) {
    switch(evt->event_id) {
        case HTTP_EVENT_ON_DATA:
            ESP_LOGI(TAG, "Ricevuti %d byte di dati", evt->data_len);
            break;
        default:
            break;
    }
    return ESP_OK;
}

// Funzione che costruisce e invia l'email
bool send_email_brevo(const char* to_email, const char* to_name,const char* subject, const char* html_content) {
    // 1. Crea JSON payload
    cJSON *root = cJSON_CreateObject();
    cJSON *sender = cJSON_CreateObject();
    cJSON_AddStringToObject(sender, "name", "ESP32 Sender");
    cJSON_AddStringToObject(sender, "email", "bruno.galluzzo2@gmail.com");
    cJSON_AddItemToObject(root, "sender", sender);

    cJSON *to_array = cJSON_CreateArray();
    cJSON *to_obj = cJSON_CreateObject();
    cJSON_AddStringToObject(to_obj, "email", to_email);
    cJSON_AddStringToObject(to_obj, "name", to_name);
    cJSON_AddItemToArray(to_array, to_obj);
    cJSON_AddItemToObject(root, "to", to_array);

    cJSON_AddStringToObject(root, "subject", subject);
    cJSON_AddStringToObject(root, "htmlContent", html_content);
    char *post_data = cJSON_PrintUnformatted(root);

    // 2. Configura HTTP client per HTTPS
    esp_http_client_config_t config = {
        .url              = "https://api.brevo.com/v3/smtp/email",
        .method           = HTTP_METHOD_POST,
        .transport_type   = HTTP_TRANSPORT_OVER_SSL,
        .event_handler    = http_event_handler,
        .crt_bundle_attach = esp_crt_bundle_attach,  
    };
    esp_http_client_handle_t client = esp_http_client_init(&config);

    esp_http_client_set_header(client, "Content-Type", "application/json");
    esp_http_client_set_header(client, "Accept", "application/json");
    esp_http_client_set_header(client, "api-key", BREVO_API_KEY);

    // 4. Imposta body e invia la richiesta
    esp_http_client_set_post_field(client, post_data, strlen(post_data));
    esp_err_t err = esp_http_client_perform(client);
    if (err == ESP_OK) {
        int status = esp_http_client_get_status_code(client);
        int len    = esp_http_client_get_content_length(client);
        ESP_LOGI(TAG, "HTTP POST status = %d, content_length = %d", status, len);
    } else {
        ESP_LOGE(TAG, "Errore HTTP POST: %s", esp_err_to_name(err));
        return false;
    }

    // 5. Cleanup
    esp_http_client_cleanup(client);
    cJSON_Delete(root);
    free(post_data);
    return true;
}


esp_err_t email_send(const char *input,httpd_req_t *req){
    int count = 0;
    cJSON *json = cJSON_Parse(input); 
    if (!json) {
        const char *err = cJSON_GetErrorPtr();
        ESP_LOGE(TAG, "JSON parse error before: %s", err ? err : "unknown");
        
        return ESP_FAIL;
    }   
    KV *array = extract_form_values_email(json, &count);
    cJSON_Delete(json);
    if (!array) {
        return ESP_FAIL;
    }

    char *email = NULL,*username = NULL,*name = NULL,*surname = NULL;

    // cleanup everything in one place
    for (int i = 0; i < count; ++i) {
        if(strcmp(array[i].key,"email")==0){
            email = strdup(array[i].value);
        }
        if(strcmp(array[i].key,"name")==0){
            name = strdup(array[i].value);
        }
        if(strcmp(array[i].key,"surname")==0){
            surname = strdup(array[i].value);
        }
        if(strcmp(array[i].key,"username")==0){
            username = strdup(array[i].value);
        }
        free(array[i].key);
        free(array[i].value);
    }
    free(array);
    if (!email) {
        ESP_LOGE(TAG, "email missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"email missing\"}",HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }
    if (!username) {
        ESP_LOGE(TAG, "username missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }
    if (!name) {
        ESP_LOGE(TAG, "name missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"name missing\"}",HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }
    if (!surname) {
        ESP_LOGE(TAG, "surname missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"surname missing\"}",HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }

    dynstr_t name_username;
    dynstr_init(&name_username);
    dynstr_append(&name_username,"Ciao ");
    dynstr_append(&name_username,name);
    dynstr_append(&name_username," ");
    dynstr_append(&name_username,surname);

    char *log = "{\"status\":\"not ok\"}";
    if(send_email_brevo(email, name_username.buf,"Email verification",template_verification)){
        log = "{\"status\":\"ok\"}";
    }
    
    dynstr_free(&name_username);
    free(email);
    free(surname);
    free(name);
    free(username);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, (const char*) log, HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}

esp_err_t send_code(const char *input,httpd_req_t *req){
    int count = 0;
    cJSON *json = cJSON_Parse(input); 
    if (!json) {
        const char *err = cJSON_GetErrorPtr();
        ESP_LOGE(TAG, "JSON parse error before: %s", err ? err : "unknown");
        
        return ESP_FAIL;
    }   
    KV *array = extract_form_values_send_code(json, &count);
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

    char* name = get_data("/sdcard/CIPHER~1/ACCOUN~1.JSO",username,"name");
    char* surname = get_data("/sdcard/CIPHER~1/ACCOUN~1.JSO",username,"surname");
    char* email = get_data("/sdcard/CIPHER~1/ACCOUN~1.JSO",username,"email");

    dynstr_t name_username;
    dynstr_init(&name_username);
    dynstr_append(&name_username,"Ciao ");
    dynstr_append(&name_username,name);
    dynstr_append(&name_username," ");
    dynstr_append(&name_username,surname);

    char *log = "{\"status\":\"not ok\"}";

    char token[TOKEN_STR_LEN];
    if(strcmp(name,"")!=0 && strcmp(surname,"")!=0 && strcmp(email,"")!=0){
        if (generate_token(token, sizeof(token))) {
            printf("Generated token: %s\n", token);
        } else {
            printf("Buffer troppo piccolo per il token\n");
        }
        size_t buf_size = strlen(template_code) + strlen(token) + 1;
        char *html = malloc(buf_size);
        if (!html) {
            perror("malloc");
            return ESP_FAIL;
        }
        snprintf(html, buf_size, template_code, token);  
        printf("%s\n", html);

        if(send_email_brevo(email, name_username.buf,"Change Password",(const char*)html)){
            log = "{\"status\":\"ok\"}";
        }
        free(html);
    }
    
    dynstr_free(&name_username);
    free(email);
    free(surname);
    free(name);
    free(username);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, (const char*) log, HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}

esp_err_t change_password(const char *input,httpd_req_t *req){
    int count = 0;
    cJSON *json = cJSON_Parse(input); 
    if (!json) {
        const char *err = cJSON_GetErrorPtr();
        ESP_LOGE(TAG, "JSON parse error before: %s", err ? err : "unknown");
        
        return ESP_FAIL;
    }   
    KV *array = extract_form_values_email(json, &count);
    cJSON_Delete(json);
    if (!array) {
        return ESP_FAIL;
    }

    char *code = NULL,*password = NULL,*username = NULL;

    // cleanup everything in one place
    for (int i = 0; i < count; ++i) {
        if(strcmp(array[i].key,"code")==0){
            code = strdup(array[i].value);
        }
        if(strcmp(array[i].key,"password")==0){
            password = strdup(array[i].value);
        }
        if(strcmp(array[i].key,"username")==0){
            username = strdup(array[i].value);
        }
        free(array[i].key);
        free(array[i].value);
    }
    free(array);
    if (!code) {
        ESP_LOGE(TAG, "code missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"code missing\"}",HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }
    if (!password) {
        ESP_LOGE(TAG, "password missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"password missing\"}",HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }
    if (!username) {
        ESP_LOGE(TAG, "username missing in JSON");
        httpd_resp_set_type(req, "application/json");
        httpd_resp_send(req,"{\"status\":\"error\",\"message\":\"username missing\"}",HTTPD_RESP_USE_STRLEN);
        return ESP_FAIL;
    }

    char *log = "{\"status\":\"not ok\"}";
    if(change_password_json("/sdcard/CIPHER~1/ACCOUN~1.JSO",username,password)){
        log = "{\"status\":\"ok\"}";
    }

    free(code);
    free(password);
    free(username);
    
    httpd_resp_set_type(req, "application/json");
    httpd_resp_send(req, (const char*) log, HTTPD_RESP_USE_STRLEN);

    return ESP_OK;
}