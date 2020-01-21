#include "freertos/FreeRTOS.h"
#include "esp_task_wdt.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_event_loop.h"
#include "nvs_flash.h"
#include "driver/gpio.h"
#include "Arduino.h"

#define LED_GPIO_PIN                     5
#define WIFI_CHANNEL_SWITCH_INTERVAL  (500)
#define WIFI_CHANNEL_MAX               (13)

uint8_t level = 0, channel = 1;
static wifi_country_t wifi_country = {.cc="CN", .schan = 1, .nchan = 13}; //Most recent esp32 library struct
typedef struct {
  unsigned protocol_version:2;
  unsigned type:2;
  unsigned subtype:4;
  unsigned toDS:1;
  unsigned fromDS:1;
  unsigned moreFragments:1;
  unsigned retry:1;
  unsigned powerManagement:1;
  unsigned moreData:1;
  unsigned WEP:1;
  unsigned order:1;
} frame_control;

typedef struct {
  frame_control framecontrol;
  uint8_t addr1[6]; /* receiver address */
  uint8_t addr2[6]; /* sender address */
  uint8_t addr3[6]; /* filtering address */
  unsigned fragment_number:4;
  unsigned sequence_number:12;
  uint8_t addr4[6]; /* optional */
} wifi_ieee80211_mac_hdr_t;

typedef struct {
  ulong time;
  uint8_t addr[6];
  unsigned sequence_number:12;
} device;

typedef struct {
  wifi_ieee80211_mac_hdr_t hdr;
  uint8_t payload[0]; /* network data ended with 4 bytes csum (CRC32) */
} wifi_ieee80211_packet_t;





// METHODS
static esp_err_t event_handler(void *ctx, system_event_t *event);
static void wifi_sniffer_init(void);
static void wifi_sniffer_set_channel(uint8_t channel);
static const char *wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type);
static void wifi_sniffer_packet_handler(void *buff, wifi_promiscuous_pkt_type_t type);


void addDevice(uint8_t newDevice[6], unsigned sequence_number);
int compareMAC(uint8_t compAddr[6]);
int searchFreeIndex();
void checkDevices();
bool toDSFilter(wifi_ieee80211_mac_hdr_t *hdr);
bool probeRequestFilter(wifi_ieee80211_mac_hdr_t *hdr);
bool RTSFilter(wifi_ieee80211_mac_hdr_t *hdr);


esp_err_t event_handler(void *ctx, system_event_t *event) {
  return ESP_OK;
}

void wifi_sniffer_init(void)
{
  nvs_flash_init();
  tcpip_adapter_init();
  ESP_ERROR_CHECK( esp_event_loop_init(event_handler, NULL) );
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  ESP_ERROR_CHECK( esp_wifi_init(&cfg) );
  ESP_ERROR_CHECK( esp_wifi_set_country(&wifi_country) ); /* set country for channel range [1, 13] */
  ESP_ERROR_CHECK( esp_wifi_set_storage(WIFI_STORAGE_RAM) );
  ESP_ERROR_CHECK( esp_wifi_set_mode(WIFI_MODE_STA) );
  ESP_ERROR_CHECK( esp_wifi_start() );
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_packet_handler);
}

void wifi_sniffer_set_channel(uint8_t channel)
{
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

const char * wifi_sniffer_packet_type2str(wifi_promiscuous_pkt_type_t type)
{
  switch(type) {
  case WIFI_PKT_MGMT: return "MGMT";
  case WIFI_PKT_DATA: return "DATA";
  default:  
  case WIFI_PKT_MISC: return "MISC";
  }
}

////////////////////
////////////////////

device devices[20];
int devicecounter = 0;
void setup() {
  Serial.begin(9600);
  delay(10);
  wifi_sniffer_init();
  pinMode(LED_GPIO_PIN, OUTPUT);
}
void loop() {
  delay(1000); 
  vTaskDelay(50);
  wifi_sniffer_set_channel(channel);
  checkDevices();
  channel = (channel % WIFI_CHANNEL_MAX) + 1;  
}


void wifi_sniffer_packet_handler(void* buff, wifi_promiscuous_pkt_type_t type)
{
  wifi_promiscuous_pkt_t *ppkt = (wifi_promiscuous_pkt_t *)buff;
  wifi_ieee80211_packet_t *ipkt = (wifi_ieee80211_packet_t *)ppkt->payload;
  wifi_ieee80211_mac_hdr_t *hdr = &ipkt->hdr;
  //if(type != WIFI_PKT_MGMT)
    //return;
  
  if(ppkt->rx_ctrl.rssi > -75) { // -75db reduces scan size to small room 
    if(probeRequestFilter(hdr) || toDSFilter(hdr) || RTSFilter(hdr)) { //Filter
      Serial.println(hdr->sequence_number, DEC);
      printf("PACKET TYPE=%s, CHAN=%02d, RSSI=%02d, SUBTYPE=%02x, ToDS=%d, FromDS=%d"
      " ADDR1=%02x:%02x:%02x:%02x:%02x:%02x,"
      " ADDR2=%02x:%02x:%02x:%02x:%02x:%02x,"
      " ADDR3=%02x:%02x:%02x:%02x:%02x:%02x\n",
      wifi_sniffer_packet_type2str(type),
      ppkt->rx_ctrl.channel,
      ppkt->rx_ctrl.rssi,
      hdr->framecontrol.subtype,
      hdr->framecontrol.toDS,
      hdr->framecontrol.fromDS,
      hdr->addr1[0],hdr->addr1[1],hdr->addr1[2],
      hdr->addr1[3],hdr->addr1[4],hdr->addr1[5],
      hdr->addr2[0],hdr->addr2[1],hdr->addr2[2],
      hdr->addr2[3],hdr->addr2[4],hdr->addr2[5],
      hdr->addr3[0],hdr->addr3[1],hdr->addr3[2],
      hdr->addr3[3],hdr->addr3[4],hdr->addr3[5]
      );
    }
  delay(1);
  }
}
bool toDSFilter(wifi_ieee80211_mac_hdr_t *hdr) {
  if((hdr->framecontrol.toDS == 1) && (hdr->framecontrol.fromDS == 0)) {
    addDevice(hdr->addr2, hdr->sequence_number);
    return true;
  }
  return false;
}
bool probeRequestFilter(wifi_ieee80211_mac_hdr_t *hdr) {
  if(hdr->framecontrol.subtype == 0x04) {
    addDevice(hdr->addr2, hdr->sequence_number);
    return true;
  }
  return false;
}
bool RTSFilter(wifi_ieee80211_mac_hdr_t *hdr) {
  if((hdr->framecontrol.subtype == 0x1b) && (hdr->framecontrol.type == 0x01)) {
    addDevice(hdr->addr2, hdr->sequence_number);
    return true;
  }
  return false;
}

void addDevice(uint8_t newDevice[6], unsigned sequence_number) {
  //Serial.println("Try to add new Device");
  int isSameAs = compareMAC(newDevice);
  if(isSameAs == -1) {
    int freeIndex = searchFreeIndex();
    if(freeIndex != -1) {
      for (size_t i = 0; i < 6; i++) {
        devices[freeIndex].addr[i] = newDevice[i];
        devices[freeIndex].time = millis();
      }
      devicecounter++;
      Serial.printf("Add device: %02x:%02x:%02x:%02x:%02x:%02x | Devices found: %d\n", newDevice[0], newDevice[1], newDevice[2], newDevice[3], newDevice[4], newDevice[5], devicecounter);
    }
  } else {
    devices[isSameAs].time = millis();
  }
}
int compareMAC(uint8_t compAddr[6]) {

  for (size_t i = 0; i < 20; i++)
  {
    if((compAddr[0] == devices[i].addr[0]) && (compAddr[1] == devices[i].addr[1]) && (compAddr[2] == devices[i].addr[2]) && (compAddr[3] == devices[i].addr[3]) && (compAddr[4] == devices[i].addr[4]) && (compAddr[5] == devices[i].addr[5])) {
      return i;
    }
  }
  return -1;
}
int searchFreeIndex() {
  for (size_t i = 0; i < 20; i++)
  {
    if(devices[i].addr[0] == 0) {
      Serial.println("Found free index");
      return i;
    }
  }
  return -1;
}
void checkDevices() {
  
  for (size_t i = 0; i < 20; i++)
  {
    if(devices[i].time != 0) {
      if((millis() - devices[i].time) > 35000 && (devices[i].time != 0)) {
        devicecounter--;
        Serial.printf("Remove device: %02x:%02x:%02x:%02x:%02x:%02x | Devices found: %d\n", devices[i].addr[0], devices[i].addr[1], devices[i].addr[2], devices[i].addr[3], devices[i].addr[4], devices[i].addr[5], devicecounter);
        devices[i].time = 0;
        for (size_t j = 0; j < 6; j++) {
          devices[i].addr[j] = 0;
        }
      }
    }
  }
}









  //printf("NEWADDRESS=%02x:%02x:%02x:%02x:%02x:%02x", compAddr[0], compAddr[1], compAddr[2], compAddr[3], compAddr[4], compAddr[5]);
 // for (size_t i = 0; i < (sizeof(devices) / sizeof(devices[0])); i++)
 // {
  //  printf("entry %d : Content: %02x:%02x:%02x:%02x:%02x:%02x", i, devices[i], devices[i].addr[0], devices[i].addr[1], devices[i].addr[2], devices[i].addr[3], devices[i].addr[4], devices[i].addr[5]);
  //}
  