#include "https.c"

void app_main(void)
{

    if(!fun_card()){
        ESP_LOGE(TAG, "SD failed");
        return;
    }
    // 1) monta SD
    if(!sd_mount()){
        ESP_LOGE(TAG,"Errore mount");
    }

    buttonSemaphore = xSemaphoreCreateBinary();
    button_configuration(BUTTON_GPIO);
    xTaskCreate(button_task, "button_task", 4096, NULL, 5, NULL);


    // 2) init NVS (per Wi‑Fi)
    ESP_ERROR_CHECK( nvs_flash_init() );

    // 3) init netif + default loop (una sola volta)
    ESP_ERROR_CHECK( esp_netif_init() );
    ESP_ERROR_CHECK( esp_event_loop_create_default() );
    esp_netif_create_default_wifi_sta();

    // 4) scan & select
    if (!wifi_scan_and_select()) {
        ESP_LOGE(TAG, "No matching AP found");
        
        return;
    }

    // 5) connect & wait IP
    if (!wifi_connect_and_wait()) {
        ESP_LOGE(TAG, "Wi‑Fi connect failed");
        return;
    }
    web_server();
    
}
