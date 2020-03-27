#ifndef INCLUDE_MOD_HTTP_H_
#define INCLUDE_MOD_HTTP_H_

#include <c_types.h>

#define HTTP_PATH_PREFIX						"http://"
#define HTTPS_PATH_PREFIX						"https://"

#define HTTP_TX_BUFFER_SIZE						1024
#define HTTP_HEADERS_BUFFER_SIZE				2096
#define HTTP_HEADER_BUFFER_SIZE					512

#define HTTP_HEADERS_NL 						"\r\n"
#define HTTP_HEADERS_DELIM 						"\r\n\r\n"
#define HTTP_HEADERS_TRANSFER_ENCODING			"Transfer-Encoding"
#define HTTP_HEADERS_CONTENT_LENGTH				"Content-Length"

#define HTTP_TRANSFER_ENCODING_CHUNKED			"chunked"

#define HTTP_PARSE_OK							0
#define HTTP_PARSE_ERROR_HEADERS				1
#define HTTP_PARSE_ERROR_CONTENT_LENGTH			2
#define HTTP_PARSE_ERROR_BLOCK_LENGTH			3

#define HTTP_URL_INVALID						-1
#define HTTP_URL_HTTP							0
#define HTTP_URL_HTTPS							1

#define SNTP_URL								"pool.ntp.org"
#define TLS_HANDSHAKE_BUFFER_SIZE				8192

int parse_url(const char* const input_url, char* output_hostname, char* output_path);
void parse_http_headers(const char* input_http_response, char* output_headers);
void parse_http_header(const char* headers, const char* header_name, char* output_header_value);
int parse_http_body(const char* input_http_response, char* output_body);
bool is_end_of_content(const char* input_context);

#endif /* INCLUDE_MOD_HTTP_H_ */
