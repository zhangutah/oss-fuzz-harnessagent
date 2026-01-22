// Generate a fuzz driver based the given function signature in CPP language. 
//  You can call the following tools to get more information about the code.
//  Prefer higher-priority tools first; only use view_code when you already know the exact file path and a line number:
//  
//  1) get_symbol_header_tool — Get the header file(s) needed for a symbol. Try an absolute path first (e.g., #include "/path/to/header.h"). If that fails with ".h file not found", try a project-relative path.
//  2) get_symbol_definition_tool — Get the definition of a symbol (the function body or struct/class definition).
//  3) get_symbol_declaration_tool — Get the declaration (prototype/signature) of a symbol.
//  4) get_symbol_references_tool — Get the references/usage of a symbol within the codebase.
//  5) get_struct_related_functions_tool — Get helper functions that operate on a struct/class (e.g., init, destroy, setters/getters).
//  6) view_code — View code around a specific file path and target line. Use this only when the path and line are known; keep context_window small.
//  7) get_file_location_tool - Get the absolute path of a file in the project codebase.
//  8) get_driver_example_tool - Randomly select one harness file in the container and return its content. 
// 
//  Guardrails:
//  - Don't call view_code repeatedly to browse; instead, first retrieve definitions/headers/references to precisely locate what you need.
//  - Avoid requesting huge windows; stay within a small context_window unless specifically needed.
// 
// @ examples of API usage:
// // Example 1:
// 
// // int http__read(struct mosquitto *mosq)
// //{
// //	ssize_t read_length;
// //	ssize_t header_length;
// //	enum mosquitto_client_state state;
// //	size_t hlen;
// //	const char *http_method, *http_path;
// //	size_t http_method_len, http_path_len;
// //	int http_minor_version;
// //	size_t http_header_count = 100;
// //	struct phr_header http_headers[100];
// //	const char *client_key = NULL;
// //	size_t client_key_len = 0;
// //	char *accept_key;
// //	bool header_have_upgrade;
// //	bool header_have_connection;
// //	struct mosquitto__packet *packet;
// //	int rc;
// //	const char *subprotocol = NULL;
// //	int subprotocol_len = 0;
// //
// //	if(!mosq){
// //		return MOSQ_ERR_INVAL;
// //	}
// //	if(mosq->sock == INVALID_SOCKET){
// //		return MOSQ_ERR_NO_CONN;
// //	}
// //
// //	state = mosquitto__get_state(mosq);
// //	if(state == mosq_cs_connect_pending){
// //		return MOSQ_ERR_SUCCESS;
// //	}
// //
// //	hlen = strlen((char *)mosq->in_packet.packet_buffer);
// //	read_length = net__read(mosq, &mosq->in_packet.packet_buffer[hlen], mosq->in_packet.packet_buffer_size-hlen);
// //	if(read_length <= 0){
// //		if(read_length == 0){
// //			return MOSQ_ERR_CONN_LOST; /* EOF */
// //		}
// //#ifdef WIN32
// //		errno = WSAGetLastError();
// //#endif
// //		if(errno == EAGAIN || errno == COMPAT_EWOULDBLOCK){
// //			return MOSQ_ERR_SUCCESS;
// //		}else{
// //			switch(errno){
// //				case COMPAT_ECONNRESET:
// //					return MOSQ_ERR_CONN_LOST;
// //				case COMPAT_EINTR:
// //					return MOSQ_ERR_SUCCESS;
// //				default:
// //					return MOSQ_ERR_ERRNO;
// //			}
// //		}
// //	}
// //
// //	mosq->in_packet.packet_buffer[mosq->in_packet.packet_buffer_size-1] = '\0'; /* Always 0 terminate */
// //	header_length = phr_parse_request((char *)mosq->in_packet.packet_buffer, strlen((char *)mosq->in_packet.packet_buffer),
// //			&http_method, &http_method_len,
// //			&http_path, &http_path_len,
// //			&http_minor_version,
// //			http_headers, &http_header_count,
// //			0);
// //	// FIXME - deal with partial read !
// //	if(header_length == -2){
// //		// Partial read
// //		return MOSQ_ERR_SUCCESS;
// //	}else if(header_length == -1){
// //		// Error
// //		return MOSQ_ERR_UNKNOWN;
// //	}else if(header_length < read_length){
// //		/* Excess data which can't be handled because the client doesn't have a key yet */
// //		return MOSQ_ERR_MALFORMED_PACKET;
// //	}
// //
// //	if(strncmp(http_method, "GET", http_method_len) && strncmp(http_method, "HEAD", http_method_len)){
// //		/* FIXME Not supported - send 501 response */
// //		return MOSQ_ERR_UNKNOWN;
// //	}
// //
// //	header_have_upgrade = false;
// //	header_have_connection = false;
// //	subprotocol = NULL;
// //
// //	for(size_t i=0; i<http_header_count; i++){
// //		if(!strncasecmp(http_headers[i].name, "Upgrade", http_headers[i].name_len)){
// //			if(!strncasecmp(http_headers[i].value, "websocket", http_headers[i].value_len)){
// //				header_have_upgrade = true;
// //			}
// //		}else if(!strncasecmp(http_headers[i].name, "Connection", http_headers[i].name_len)){
// //			/* Check for "upgrade" */
// //			const char *str = http_headers[i].value;
// //			size_t start = 0;
// //			size_t j;
// //			for(j=0; j<http_headers[i].value_len; j++){
// //				if(str[j] == ','){
// //					if(!strncasecmp(&str[start], "upgrade", http_headers[i].value_len-j)){
// //						header_have_connection = true;
// //						break;
// //					}else{
// //						start = j+1;
// //					}
// //				}else if(str[j] == ' '){
// //					start = j+1;
// //				}
// //			}
// //			if(!strncasecmp(&str[start], "upgrade", http_headers[i].value_len-j)){
// //				header_have_connection = true;
// //			}
// //		}else if(!strncasecmp(http_headers[i].name, "Sec-WebSocket-Key", http_headers[i].name_len)){
// //			client_key = http_headers[i].value;
// //			client_key_len = http_headers[i].value_len;
// //		}else if(!strncasecmp(http_headers[i].name, "Sec-WebSocket-Version", http_headers[i].name_len)){
// //			/* Check for "13" */
// //			if(http_headers[i].value_len != 2
// //					|| http_headers[i].value[0] != '1'
// //					|| http_headers[i].value[1] != '3'
// //					){
// //
// //				/* FIXME - not supported */
// //				return MOSQ_ERR_NOT_SUPPORTED;
// //			}
// //		}else if(!strncasecmp(http_headers[i].name, "Sec-WebSocket-Protocol", http_headers[i].name_len)){
// //			/* Check for "mqtt" */
// //			if(!strncmp(http_headers[i].value, "mqtt", http_headers[i].value_len)
// //					|| !strncmp(http_headers[i].value, "mqttv3.1", http_headers[i].value_len)){
// //
// //				subprotocol = http_headers[i].value;
// //				subprotocol_len = (int)http_headers[i].value_len;
// //			}
// //		}else if(!strncasecmp(http_headers[i].name, "X-Forwarded-For", http_headers[i].name_len)){
// //			/* Before implementing this, refer to:
// //			 * https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For
// //			 *
// //			 * At the very least, a trusted proxy count must be used. A trusted
// //			 * proxy list would ideally be used.
// //			 *
// //			 * Problematic for us is that if the listener is directly
// //			 * connectable, then the use of this header is insecure. We can't
// //			 * control that, so we have to make it very clear to the end user
// //			 * that this is the case.
// //			 */
// //		}else if(!strncasecmp(http_headers[i].name, "Origin", http_headers[i].name_len)){
// //			if(mosq->listener){
// //				bool have_match = false;
// //				for(int j=0; j<mosq->listener->ws_origin_count; j++){
// //					if(!strncmp(mosq->listener->ws_origins[j], http_headers[i].value, http_headers[i].value_len)){
// //						have_match = true;
// //						break;
// //					}
// //				}
// //				if(!have_match && mosq->listener->ws_origin_count > 0){
// //					return MOSQ_ERR_HTTP_BAD_ORIGIN;
// //				}
// //			}
// //		}else{
// //			/* Unknown header */
// //		}
// //	}
// //
// //	if(subprotocol == NULL){
// //		// FIXME ?
// //		return MOSQ_ERR_UNKNOWN;
// //	}
// //
// //	if(header_have_upgrade == false || header_have_connection == false
// //			|| client_key == NULL || client_key_len == 0){
// //
// //		// FIXME - 404
// //		return MOSQ_ERR_UNKNOWN;
// //	}
// //
// //	if(ws__create_accept_key(client_key, client_key_len, &accept_key)){
// //		return MOSQ_ERR_UNKNOWN;
// //	}
// //
// //	packet = mosquitto_calloc(1, sizeof(struct mosquitto__packet) + 1024 + WS_PACKET_OFFSET);
// //	if(!packet){
// //		SAFE_FREE(accept_key);
// //		return MOSQ_ERR_NOMEM;
// //	}
// //	packet->packet_length = (uint32_t )snprintf((char *)&packet->payload[WS_PACKET_OFFSET], 1024,
// //			"HTTP/1.1 101 Switching Protocols\r\n"
// //			"Upgrade: WebSocket\r\n"
// //			"Connection: Upgrade\r\n"
// //			"Sec-WebSocket-Accept: %s\r\n"
// //			"Sec-WebSocket-Protocol: %.*s\r\n"
// //			"\r\n", accept_key, subprotocol_len, subprotocol) + WS_PACKET_OFFSET;
// //	SAFE_FREE(accept_key);
// //	packet->to_process = packet->packet_length;
// //
// //	memset(mosq->in_packet.packet_buffer, 0, db.config->packet_buffer_size);
// //	rc = packet__queue(mosq, packet);
// //	http__context_cleanup(mosq);
// //	ws__context_init(mosq);
// //	return rc;
// //}
// 
// 
// Useful project headers:
// 
// 
// 
// 
// The following function fuzzes
//     int phr_parse_request(const char * buf, size_t len, const char ** method, size_t * method_len, const char ** path, size_t * path_len, int * minor_version, struct phr_header * headers, size_t * num_headers, size_t last_len);
// 
// The fuzzer entry point is defined as follows:
// extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// Output the full driver code in reply.
#include <cstddef>
#include <cstdint>
#include <cstring>

// Include the picohttpparser header (absolute path discovered in the project)
#include "/src/mosquitto/deps/picohttpparser/picohttpparser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // phr_parse_request expects a char buffer and its length.
    const char *buf = reinterpret_cast<const char *>(Data);

    // Output parameters for phr_parse_request
    const char *method = nullptr;
    size_t method_len = 0;
    const char *path = nullptr;
    size_t path_len = 0;
    int minor_version = 0;

    // Prepare headers array. Use a reasonably large number to allow multiple headers.
    constexpr size_t MAX_HEADERS = 128;
    struct phr_header headers[MAX_HEADERS];
    // phr_parse_request expects num_headers initialized to the size of the headers array.
    size_t num_headers = MAX_HEADERS;

    // Zero the headers to avoid uninitialized data
    std::memset(headers, 0, sizeof(headers));

    // Call the parser with last_len = 0 (typical)
    // Cast to void to explicitly ignore the returned int (we are fuzzing for crashes/UB).
    (void)phr_parse_request(buf, Size,
                            &method, &method_len,
                            &path, &path_len,
                            &minor_version,
                            headers, &num_headers,
                            0);

    // Also try a secondary call with a non-zero last_len to exercise incremental/partial-read logic.
    // Use a value derived from Size but bounded.
    if (Size > 0) {
        num_headers = MAX_HEADERS;
        size_t last_len = (Size > 1) ? (Size / 2) : 1;
        (void)phr_parse_request(buf, Size,
                                &method, &method_len,
                                &path, &path_len,
                                &minor_version,
                                headers, &num_headers,
                                last_len);
    }

    return 0;
}