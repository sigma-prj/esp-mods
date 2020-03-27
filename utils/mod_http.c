#include "mod_http.h"

#include <osapi.h>

int parse_url(const char* const input_url, char* output_hostname, char* output_path)
{
	char local_str[HTTP_HEADER_BUFFER_SIZE];
	os_strcpy(local_str, input_url);
	int prefix_type = HTTP_URL_HTTP;

	char* pch = local_str;
	if (os_strstr(pch, HTTPS_PATH_PREFIX))
	{
		pch += os_strlen(HTTPS_PATH_PREFIX);
		prefix_type = HTTP_URL_HTTPS;
	}
	else if (os_strstr(pch, HTTP_PATH_PREFIX))
	{
		pch += os_strlen(HTTP_PATH_PREFIX);
	}

	char* delim = os_strstr(pch, "/");
	if (delim)
	{
		os_strcpy(output_path, delim);
		delim[0] = 0;
	}
	else
	{
		os_strcpy(output_path, "/");
	}
	os_strcpy(output_hostname, pch);
	return prefix_type;
}

void parse_http_headers(const char* input_http_response, char* output_headers)
{
	output_headers[0] = 0;
	char* pdelim = os_strstr(input_http_response, HTTP_HEADERS_DELIM);
	if (pdelim)
	{
		size_t sz_headers_block = pdelim + os_strlen(HTTP_HEADERS_NL) - input_http_response;
		os_memcpy(output_headers, input_http_response, sz_headers_block);
		output_headers[sz_headers_block] = 0;
	}
}

void parse_http_header(const char* headers, const char* header_name, char* output_header_value)
{
	output_header_value[0] = 0;
	char search_pattern[HTTP_HEADER_BUFFER_SIZE];
	os_sprintf(search_pattern, "%s%s: ", HTTP_HEADERS_NL, header_name);
	char* phead = strcasestr(headers, search_pattern);
	if (phead)
	{
		char* phead_val = phead + os_strlen(search_pattern);
		char* phead_end = os_strstr(phead_val, HTTP_HEADERS_NL);
		if (phead_end)
		{
			os_memcpy(output_header_value, phead_val, phead_end - phead_val);
			output_header_value[phead_end - phead_val] = 0;
		}
	}
}

bool is_end_of_content(const char* input_content)
{
	bool result = false;
	char headers[HTTP_HEADERS_BUFFER_SIZE];
	parse_http_headers(input_content, headers);
	if (os_strlen(headers) > 0)
	{
		char header_value[HTTP_HEADER_BUFFER_SIZE];
		parse_http_header(headers, HTTP_HEADERS_TRANSFER_ENCODING, header_value);
		const char* raw_body = &input_content[os_strlen(headers) + os_strlen(HTTP_HEADERS_NL)];
		if (os_strlen(header_value) > 0)
		{
			char* block_start;
			const char* block_end = raw_body;
			long int block_sz = strtol(raw_body, &block_start, 16);
			if (block_sz > 0 && os_strstr(block_start, HTTP_HEADERS_NL) == block_start)
			{
				bool overrun_content = false;
				while (block_sz > 0 && !overrun_content)
				{
					block_start += os_strlen(HTTP_HEADERS_NL);
					block_end = block_start + block_sz;
					overrun_content = ((block_end - raw_body) + os_strlen(HTTP_HEADERS_NL) > os_strlen(raw_body)) || os_strstr(block_end, HTTP_HEADERS_NL) != block_end;
					if (!overrun_content)
					{
						block_sz = strtol(block_end + os_strlen(HTTP_HEADERS_NL), &block_start, 16);
					}
				}
				result = (block_sz == 0);
			}
		}
		else
		{
			parse_http_header(headers, HTTP_HEADERS_CONTENT_LENGTH, header_value);
			if (os_strlen(header_value) > 0)
			{
				long int content_sz = strtol(header_value, NULL, 10);
				if (content_sz > 0)
				{
					result = (content_sz <= os_strlen(raw_body));
				}
				else
				{
					// Error case: Invalid Content-Length HTTP header value
					result = true;
				}
			}
			else
			{
				// Error case: Unable to identify content size
				result = true;
			}
		}
	}
	return result;
}

int parse_http_body(const char* input_http_response, char* output_body)
{
	char headers[HTTP_HEADERS_BUFFER_SIZE];
	output_body[0] = 0;
	parse_http_headers(input_http_response, headers);
	if (os_strlen(headers) > 0)
	{
		char header_value[HTTP_HEADER_BUFFER_SIZE];
		parse_http_header(headers, HTTP_HEADERS_TRANSFER_ENCODING, header_value);
		const char* raw_body = &input_http_response[os_strlen(headers) + os_strlen(HTTP_HEADERS_NL)];
		if (os_strlen(header_value) > 0)
		{
			char* block_start;
			char* block_end;
			size_t out_idx = 0;
			long int block_sz = strtol(raw_body, &block_start, 16);
			while (block_sz > 0)
			{
				block_start += os_strlen(HTTP_HEADERS_NL);
				block_end = block_start + block_sz;
				if (block_end - raw_body > os_strlen(raw_body))
				{
					return HTTP_PARSE_ERROR_BLOCK_LENGTH;
				}
				os_memcpy(&output_body[out_idx], block_start, block_sz);
				out_idx += block_sz;
				block_sz = strtol(block_end + os_strlen(HTTP_HEADERS_NL), &block_start, 16);
			}
			output_body[out_idx] = 0;
			return HTTP_PARSE_OK;
		}
		else
		{
			parse_http_header(headers, HTTP_HEADERS_CONTENT_LENGTH, header_value);
			if (os_strlen(header_value) > 0)
			{
				long int content_sz = strtol(header_value, NULL, 10);
				if (content_sz > 0 && content_sz <= os_strlen(raw_body))
				{
					os_memcpy(output_body, raw_body, content_sz);
					output_body[content_sz] = 0;
					return HTTP_PARSE_OK;
				}
			}
			return HTTP_PARSE_ERROR_CONTENT_LENGTH;
		}
	}
	return HTTP_PARSE_ERROR_HEADERS;
}
