#include <osapi.h>
#include <mem.h>
#include <user_interface.h>
#include <gpio.h>
#include <espconn.h>
#include <sntp.h>
#include <json/jsonparse.h>

#include "mod_http.h"

// Update according to WiFi session ID
#define WIFI_SSID								"SSID"
// Update according to WiFi session password
#define WIFI_PASSPHRASE							"PASSWORD"
// HTTP(S) URL to query using HTTP GET method
#define HTTP_QUERY_URL							"https://openweathermap.org/data/2.5/weather?lat=51.905291&lon=4.466412&appid=439d4b804bc8187953eb36d2a8c26a02"
// JSON tag name to extract
#define JSON_TAG_WEATHER_TEMPR					"temp"
// JSON tag depth level to extract
#define JSON_DEPTH_WEATHER_TEMPR				3

#define UART_BAUD_RATE							115200
#define UART_LOCAL_RX_BUFFER_SIZE				128
#define LABEL_BUFFER_SIZE						128

#define SYSTEM_PARTITION_RF_CAL_SZ				0x1000
#define SYSTEM_PARTITION_PHY_DATA_SZ			0x1000
#define SYSTEM_PARTITION_SYSTEM_PARAMETER_SZ	0x3000

#define SYSTEM_SPI_SIZE							0x400000

#define SYSTEM_PARTITION_RF_CAL_ADDR			SYSTEM_SPI_SIZE - SYSTEM_PARTITION_SYSTEM_PARAMETER_SZ - SYSTEM_PARTITION_PHY_DATA_SZ - SYSTEM_PARTITION_RF_CAL_SZ
#define SYSTEM_PARTITION_PHY_DATA_ADDR			SYSTEM_SPI_SIZE - SYSTEM_PARTITION_SYSTEM_PARAMETER_SZ - SYSTEM_PARTITION_PHY_DATA_SZ
#define SYSTEM_PARTITION_SYSTEM_PARAMETER_ADDR	SYSTEM_SPI_SIZE - SYSTEM_PARTITION_SYSTEM_PARAMETER_SZ

static const uint16 GPIO_PIN_LED = 2;
static const uint16 HEARTBEAT_FLASH_DELAY = 10 * 1000;
static os_timer_t start_timer;
static uint16 tick_index = 0;

// local_uart_rx_buf is used to store received input UART data
static uint8 local_uart_rx_buf[UART_LOCAL_RX_BUFFER_SIZE] = { 0 };
// index - used for cursor position tracking at receive buffer
static size_t local_http_receive_idx = 0;
// used to resolve target hostname ip address by DNS
static ip_addr_t target_server_ip;
// used to store url prefix type (HTTP or HTTPS)
static int url_prefix_type = HTTP_URL_HTTP;
// used to store http hostname
static char http_hostname[HTTP_HEADER_BUFFER_SIZE];
// used to store http path
static char http_path[HTTP_HEADER_BUFFER_SIZE];
// used to indicate whether SNTP service was activated
static bool is_sntp_active = false;
// used to indicate whether HTTP data transfer has been completed
static bool is_transfer_completed = false;
// this buffer is used to persist HTTP content
static char* http_content = NULL;
// actual connection definition used to perform HTTP GET request
struct espconn* pespconn = NULL;

static const partition_item_t part_table[] =
{
	{ SYSTEM_PARTITION_RF_CAL,				SYSTEM_PARTITION_RF_CAL_ADDR,			SYSTEM_PARTITION_RF_CAL_SZ				},
	{ SYSTEM_PARTITION_PHY_DATA,			SYSTEM_PARTITION_PHY_DATA_ADDR,			SYSTEM_PARTITION_PHY_DATA_SZ			},
	{ SYSTEM_PARTITION_SYSTEM_PARAMETER,	SYSTEM_PARTITION_SYSTEM_PARAMETER_ADDR,	SYSTEM_PARTITION_SYSTEM_PARAMETER_SZ	}
};

// ##################################### SAMPLE COMMANDS #####################################

// ******************************** CONNECTION STATUS COMMAND *********************************

static bool is_station_connected(void)
{
	return wifi_station_get_connect_status() == STATION_GOT_IP;
}

static bool is_secure(void)
{
	return url_prefix_type == HTTP_URL_HTTPS;
}

static void connection_status(void)
{
	char label_status[LABEL_BUFFER_SIZE];
	uint8 status = wifi_station_get_connect_status();
	lookup_station_status(label_status, status);
	os_printf("\n[INFO] Current connection status: %s\n", label_status);
}

// *********************************** WIFI SCAN COMMAND ***********************************

static void ICACHE_FLASH_ATTR connection_scan_completed_callback(void *arg, STATUS status)
{
	int ret;
	char ssid_name[LABEL_BUFFER_SIZE];
	char ssid_cipher[LABEL_BUFFER_SIZE];
	if (status == OK)
	{
		struct bss_info *bss_link = (struct bss_info*)arg;
		while (bss_link != NULL)
		{
			if (bss_link->ssid_len)
			{
				os_memcpy(ssid_name, bss_link->ssid, bss_link->ssid_len);
				lookup_cipher(ssid_cipher, bss_link->group_cipher);
				ssid_name[bss_link->ssid_len] = 0;
				os_printf("\t- SSID: %s, channel: %d, freqcal_val: %d, freq_offset: %d, cipher: %s\n", ssid_name, bss_link->channel,
							bss_link->freqcal_val, bss_link->freq_offset, ssid_cipher);
			}
			bss_link = bss_link->next.stqe_next;
		}
		os_printf("[INFO] Scan has been completed successfully\n");
	} else {
		os_printf("[ERROR] Scan procedure has failed: %d\n", status);
	}
}

void scan_sessions(void)
{
	os_printf("\n[INFO] Scanning for available WiFi networks ...\n");
	wifi_station_scan(NULL, connection_scan_completed_callback);
}

// ******************************** WIFI CONNECT\DISCONNECT COMMANDS ********************************

void connection_configure(void)
{
	char ssid[] = WIFI_SSID;
	char password[] = WIFI_PASSPHRASE;
	struct station_config sta_conf = { 0 };

	os_memcpy(sta_conf.ssid, ssid, sizeof(ssid));
	os_memcpy(sta_conf.password, password, sizeof(password));
	wifi_station_set_config(&sta_conf);
	wifi_station_set_auto_connect(1);
}

void connect(void)
{
	if (!is_station_connected())
	{
		os_printf("\n[INFO] Connecting to predefined SSID ...\n");
		connection_configure();
		if (wifi_station_connect())
		{
			os_printf("[INFO] Command \"connect\" has been submitted\n");
		}
		else
		{
			os_printf("[ERROR] Unable to submit \"connect\" command\n");
		}
	}
	else
	{
		os_printf("\n[INFO] Already connected\n");
	}
}

void disconnect(void)
{
	os_printf("\n[INFO] Disconnecting from predefined SSID ...\n");
	wifi_station_set_auto_connect(0);
	if (wifi_station_disconnect())
	{
		os_printf("[INFO] Command \"disconnect\" has been submitted\n");
	}
	else
	{
		os_printf("[ERROR] Unable to submit \"disconnect\" command\n");
	}
}

// ******************************** COMMAND TO PERFORM SAMPLE HTTP REQUEST ********************************

// Forward-declarations

void release_espconn_memory(struct espconn* pconn);

// Callback methods

static void ICACHE_FLASH_ATTR on_dns_ip_resoved_callback(const char* hostnaname, ip_addr_t* ip, void* arg);
static void ICACHE_FLASH_ATTR on_tcp_connected_callback(void* arg);
static void ICACHE_FLASH_ATTR on_tcp_receive_data_callback(void* arg, char* user_data, unsigned short len);
static void ICACHE_FLASH_ATTR on_tcp_send_data_callback(void* arg);
static void ICACHE_FLASH_ATTR on_tcp_close_callback(void* arg);
static void ICACHE_FLASH_ATTR on_tcp_failed_callback(void* arg, sint8 error_type);

// ON IP ADDRESS RESOLVED BY HOSTNAME callback method

static void ICACHE_FLASH_ATTR on_dns_ip_resoved_callback(const char* hostnaname, ip_addr_t* ip, void* arg)
{
	struct espconn* pconn = (struct espconn*)arg;
	if (ip)
	{
		os_printf("[INFO] IP address by hostname `%s` is resolved: %d.%d.%d.%d\n",
				hostnaname,
				*((uint8*)&ip->addr),
				*((uint8*)&ip->addr+1),
				*((uint8*)&ip->addr+2),
				*((uint8*)&ip->addr+3));
		// TCP port configured to 80 (or 433) to make standard HTTP (or HTTPS) request
		if (is_secure())
		{
			pconn->proto.tcp->remote_port = 443;
		}
		else
		{
			pconn->proto.tcp->remote_port = 80;
		}
		// TCP IP address configured to value resolved by DNS
		os_memcpy(pconn->proto.tcp->remote_ip, &ip->addr, 4);
		espconn_regist_connectcb(pconn, on_tcp_connected_callback);
		espconn_regist_reconcb(pconn, on_tcp_failed_callback);
		char res_status[LABEL_BUFFER_SIZE];
		// Establishes TCP connection
		if (is_secure())
		{
			espconn_secure_set_size(0x01, TLS_HANDSHAKE_BUFFER_SIZE);
			sint8 res = espconn_secure_connect(pconn);
			lookup_espconn_error(res_status, res);
			os_printf("[INFO] Establishing secure TCP connection... %s\n", res_status);
		}
		else
		{
			sint8 res = espconn_connect(pconn);
			lookup_espconn_error(res_status, res);
			os_printf("[INFO] Establishing TCP connection... %s\n", res_status);
		}
	}
	else
	{
		os_printf("[ERROR] Unable get IP address by hostname `%s`\n", hostnaname);
		release_espconn_memory(pconn);
	}
}

// ON-SUCCESSFUL TCP CONNECT callback method (triggered upon TCP connection is established, but download has not stared yet)

static void ICACHE_FLASH_ATTR on_tcp_connected_callback(void* arg)
{
	os_printf("[INFO] TCP connection is established\n");
	struct espconn* pconn = (struct espconn*)arg;
	espconn_regist_disconcb(pconn, on_tcp_close_callback);
	espconn_regist_recvcb(pconn, on_tcp_receive_data_callback);
	espconn_regist_sentcb(pconn, on_tcp_send_data_callback);

	char tx_buf[HTTP_TX_BUFFER_SIZE];
	os_sprintf(tx_buf, "GET %s HTTP/1.1\r\nHost: %s\r\nAccept: */*\r\n\r\n", http_path, http_hostname);
	// os_printf("[DEBUG] HTTP TX buffer:\n%s\n", tx_buf);
	if (is_secure())
	{
		espconn_secure_send(pconn, tx_buf, os_strlen(tx_buf));
	}
	else
	{
		espconn_send(pconn, tx_buf, os_strlen(tx_buf));
	}
}

// ON-SUCCESSFUL TCP DISCONNECT callback method (triggered upon successful HTTP response download completed and socket connection is closed)

static void ICACHE_FLASH_ATTR on_tcp_close_callback(void* arg)
{
	os_printf("[INFO] TCP connection closed\n");
	struct espconn* pconn = (struct espconn*)arg;
	release_espconn_memory(pconn);
}

// ON-FAILED TCP CONNECT callback method (triggered in case of TCP connection cannot be established, used for re-try logic)

static void ICACHE_FLASH_ATTR on_tcp_failed_callback(void* arg, sint8 error_type)
{
	char error_info[LABEL_BUFFER_SIZE];
	lookup_espconn_error(error_info, error_type);
	os_printf("[ERROR] Failed to establish TCP connection: %s\n", error_info);
	struct espconn* pconn = (struct espconn*)arg;
	release_espconn_memory(pconn);
}

// TCP DATA RECEIVE callback method

static void ICACHE_FLASH_ATTR on_tcp_receive_data_callback(void* arg, char* user_data, unsigned short len)
{
	if (!is_transfer_completed)
	{
		os_printf("[DEBUG] On TCP data receive callback handler. Bytes received: %d.\n", len);
		char* local_content = (char*)os_malloc(local_http_receive_idx + len + 1);
		if (local_http_receive_idx > 0)
		{
			os_memcpy(local_content, http_content, local_http_receive_idx);
			os_free(http_content);
		}
		os_memcpy(&local_content[local_http_receive_idx], user_data, len);
		http_content = local_content;
		local_http_receive_idx += len;
		http_content[local_http_receive_idx] = 0;
		if (is_end_of_content(http_content))
		{
			local_http_receive_idx = 0;
			os_printf("[INFO] Full HTTP content has been received\n");
			// os_printf("[DEBUG] Received HTTP Content:\n%s\n", http_content);
			is_transfer_completed = true;
		}
	}
}

// TCP DATA SEND callback method

static void ICACHE_FLASH_ATTR on_tcp_send_data_callback(void* arg)
{
	os_printf("[INFO] On TCP data send callback handler\n");
}

// Releases ESP connection resources
void release_espconn_memory(struct espconn* pconn)
{
	if (pconn)
	{
		if (pconn->proto.tcp)
		{
			os_free(pconn->proto.tcp);
			pconn->proto.tcp = NULL;
		}
		os_printf("[INFO] TCP connection resources released\n");
		os_free(pconn);
		pespconn = NULL;
	}
}

// Actual HTTP request execution
void http_request(const char* url)
{
	// Memory allocation for pespconn
	pespconn = (struct espconn*)os_zalloc(sizeof(struct espconn));
	// ESP connection setup for TCP
	pespconn->type = ESPCONN_TCP;
	pespconn->state = ESPCONN_NONE;
	// Configuring ESP TCP settings
	pespconn->proto.tcp = (esp_tcp *)os_zalloc(sizeof(esp_tcp));
	// Performing basic URL parsing to extract hostname and HTTP path
	url_prefix_type = parse_url(HTTP_QUERY_URL, http_hostname, http_path);
	// Resolve IP address by hostname
	os_printf("[INFO] Trying to resolve IP address by hostname `%s` ...\n", http_hostname);
	// Clean HTTP Content loaded on previous submission
	if (http_content)
	{
		os_free(http_content);
		http_content = NULL;
	}
	espconn_gethostbyname(pespconn, http_hostname, &target_server_ip, on_dns_ip_resoved_callback);
}

// HTTP JSON Content Parsing
void process_content(void)
{
	if (http_content)
	{
		char* json_body = (char*)os_malloc(os_strlen(http_content));
		parse_http_body(http_content, json_body);
		os_printf("[INFO] JSON Body:\n%s\n\n", json_body);

		// JSON Parsing
		struct jsonparse_state parser;
		jsonparse_setup(&parser, json_body, os_strlen(json_body));
		int node_type;
		char value_buffer[LABEL_BUFFER_SIZE];
		os_bzero(value_buffer, LABEL_BUFFER_SIZE);
		bool result_found = false;
		while ((node_type = jsonparse_next(&parser)) != 0 && !result_found)
		{
			if (node_type == JSON_TYPE_PAIR_NAME && jsonparse_strcmp_value(&parser, JSON_TAG_WEATHER_TEMPR) == 0
											&& jsonparse_get_len(&parser) == os_strlen(JSON_TAG_WEATHER_TEMPR)
											&& parser.depth == JSON_DEPTH_WEATHER_TEMPR)
			{
				jsonparse_next(&parser);
				node_type = jsonparse_next(&parser);
				if (node_type == JSON_TYPE_NUMBER)
				{
					jsonparse_copy_value(&parser, value_buffer, sizeof(value_buffer));
					result_found = true;
				}
			}
		}

		if (result_found)
		{
			os_printf("[INFO] Parsed JSON Element: Temperature value: %s\n", value_buffer);
		}
		else
		{
			os_printf("[INFO] Unable to found JSON Element with temperature value\n");
		}
		os_free(json_body);
	}
	else
	{
		os_printf("[INFO] HTTP content is empty\n");
	}
}

// **************************************** COMMANDS DISPATCHER METHOD *************************************

void process_input_command(const uint8 cmd)
{
	switch(cmd)
	{
		case 's':
		case 'S':
			scan_sessions();
			break;
		case 'c':
		case 'C':
			connect();
			break;
		case 'd':
		case 'D':
			disconnect();
			break;
		case 'i':
		case 'I':
			connection_status();
			break;
		case 't':
		case 'T':
			os_printf("[INFO] Submitting sample HTTP GET request ...\n");
			http_request(HTTP_QUERY_URL);
			break;
		case 'p':
		case 'P':
			os_printf("[INFO] Trying to parse HTTP JSON content...\n");
			process_content();
			break;
	}
}

// ############################# APPLICATION MAIN LOOP METHOD (TRIGGERED EACH 50 MS) #############################

void run_application(void* arg)
{
	++tick_index;
	if (tick_index % 20 == 0)
	{
		if (is_station_connected())
		{
			// SNTP connection initialisation (used for TLS shared key generation)
			if (!is_sntp_active)
			{
				sntp_setservername(0, SNTP_URL);
				sntp_init();
				is_sntp_active = true;
			}
			// Build-in LED Heartbeat flashing - when WiFi connection established
			GPIO_OUTPUT_SET(GPIO_PIN_LED, 0);
			os_delay_us(HEARTBEAT_FLASH_DELAY);
			GPIO_OUTPUT_SET(GPIO_PIN_LED, 1);
		}
		else
		{
			// SNTP connection shutdown
			if (is_sntp_active)
			{
				sntp_stop();
				is_sntp_active = false;
			}
			// Build-in LED is switched-off when disconnected
			GPIO_OUTPUT_SET(GPIO_PIN_LED, 1);
		}
		tick_index = 0;
	}

	// Read input from UART0
	uint16 bytes_read = rx_buff_deq(local_uart_rx_buf, UART_LOCAL_RX_BUFFER_SIZE);
	if (bytes_read)
	{
		// Echo UART input back to user
		uart0_tx_buffer(local_uart_rx_buf, bytes_read);
		// Commands Processing
		uint16 i;
		for (i = 0U; i < bytes_read; ++i)
		{
			process_input_command(local_uart_rx_buf[i]);
		}
	}

	// Close TCP socket connection upon data transfer is completed
	if (is_transfer_completed)
	{
		is_transfer_completed = false;
		if (is_secure())
		{
			espconn_secure_disconnect(pespconn);
		}
		else
		{
			espconn_disconnect(pespconn);
		}
	}
}

// ##################################### APPLICATION MAIN INIT METHODS #####################################

// Used to extend memory by extra 17 KB of iRAM
uint32 user_iram_memory_is_enabled(void)
{
	return 1;
}

void ICACHE_FLASH_ATTR user_pre_init(void)
{
	system_partition_table_regist(part_table, 3, SPI_FLASH_SIZE_MAP);
}

void ICACHE_FLASH_ATTR user_init(void)
{
	uart_init(UART_BAUD_RATE, UART_BAUD_RATE);
	gpio_init();
	PIN_FUNC_SELECT(PERIPHS_IO_MUX_GPIO2_U, FUNC_GPIO2);

	wifi_set_opmode(STATION_MODE);

	gpio_output_set(0, 0, (1 << GPIO_PIN_LED), 0);
	os_timer_setfn(&start_timer, (os_timer_func_t*)run_application, NULL);
	os_timer_arm(&start_timer, 50, 1);
}
