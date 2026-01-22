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
// // int http_c__read(struct mosquitto *mosq)
// //{
// //	ssize_t read_length;
// //	enum mosquitto_client_state state;
// //	size_t hlen;
// //	int http_status;
// //	const char *http_msg;
// //	size_t http_msg_len;
// //	int http_minor_version;
// //	size_t http_header_count = 100;
// //	struct phr_header http_headers[100];
// //	const char *client_key = NULL;
// //	size_t client_key_len = 0;
// //	size_t i;
// //	bool header_have_upgrade;
// //	bool header_have_connection;
// //	bool header_have_subprotocol;
// //	int rc = MOSQ_ERR_SUCCESS;
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
// //	hlen = strlen(mosq->http_request);
// //	read_length = net__read(mosq, &mosq->http_request[hlen], (size_t)mosq->wsd.http_header_size-hlen);
// //	if(read_length <= 0){
// //		if(read_length == 0){
// //			return MOSQ_ERR_CONN_LOST; /* EOF */
// //		}
// //		WINDOWS_SET_ERRNO();
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
// //	hlen += (size_t)read_length;
// //	mosq->http_request[hlen] = '\0';
// //
// //	read_length = phr_parse_response(mosq->http_request, hlen,
// //			&http_minor_version, &http_status,
// //			&http_msg, &http_msg_len,
// //			http_headers, &http_header_count,
// //			0);
// //	if(read_length == -2){
// //		// Partial read
// //		return MOSQ_ERR_SUCCESS;
// //	}else if(read_length == -1){
// //		// Error
// //		return MOSQ_ERR_UNKNOWN;
// //	}
// //
// //	if(http_status != 101){
// //		mosquitto_FREE(mosq->http_request);
// //		/* FIXME Not supported - send 501 response */
// //		return MOSQ_ERR_UNKNOWN;
// //	}
// //
// //	header_have_upgrade = false;
// //	header_have_connection = false;
// //	header_have_subprotocol = false;
// //
// //	for(i=0; i<http_header_count; i++){
// //		if(!strncasecmp(http_headers[i].name, "Upgrade", http_headers[i].name_len)){
// //			if(!strncasecmp(http_headers[i].value, "websocket", http_headers[i].value_len)){
// //				header_have_upgrade = true;
// //			}
// //		}else if(!strncasecmp(http_headers[i].name, "Connection", http_headers[i].name_len)){
// //			/* Check for "upgrade" */
// //			const char *str = http_headers[i].value;
// //			size_t start = 0;
// //			size_t j = 0;
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
// //		}else if(!strncasecmp(http_headers[i].name, "Sec-WebSocket-Accept", http_headers[i].name_len)){
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
// //			if(!strncmp(http_headers[i].value, "mqtt", http_headers[i].value_len)){
// //				header_have_subprotocol = true;
// //			}
// //		}else{
// //			/* Unknown header */
// //		}
// //	}
// //
// //	if(header_have_upgrade == false || header_have_connection == false || header_have_subprotocol == false
// //			|| client_key == NULL || client_key_len == 0){
// //
// //		// FIXME - 404
// //		return MOSQ_ERR_UNKNOWN;
// //	}
// //	if(strncmp(mosq->wsd.accept_key, client_key, client_key_len)){
// //		// FIXME - 50x
// //		return MOSQ_ERR_UNKNOWN;
// //	}
// //
// //	http_c__context_cleanup(mosq);
// //	ws__context_init(mosq);
// //
// //	//* FIXME outgoing properites
// //	rc = send__connect(mosq, mosq->keepalive, mosq->clean_start, NULL);
// //	if(rc){
// //		packet__cleanup_all(mosq);
// //		net__socket_close(mosq);
// //		mosquitto__set_state(mosq, mosq_cs_new);
// //	}
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
//     int phr_parse_response(const char * _buf, size_t len, int * minor_version, int * status, const char ** msg, size_t * msg_len, struct phr_header * headers, size_t * num_headers, size_t last_len);
// 
// The fuzzer entry point is defined as follows:
// extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size)
// Output the full driver code in reply.
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <cinttypes>

// Include picohttpparser header (absolute path found in the project)
#include "/src/mosquitto/deps/picohttpparser/picohttpparser.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
    // Interpret fuzzer data as the HTTP response buffer
    const char *buf = reinterpret_cast<const char *>(Data);

    // Prepare storage for headers and outputs
    const size_t kMaxHeaders = 128;
    struct phr_header headers[kMaxHeaders];
    // Zero-init to be safe
    std::memset(headers, 0, sizeof(headers));

    int minor_version = -1;
    int status = 0;
    const char *msg = nullptr;
    size_t msg_len = 0;
    size_t num_headers = kMaxHeaders;

    // Call phr_parse_response with last_len = 0 (no completeness check)
    int ret1 = phr_parse_response(buf, Size, &minor_version, &status, &msg, &msg_len, headers, &num_headers, 0);

    // Also call with a non-zero last_len to exercise that code path when possible.
    // We pick a small non-zero value derived from Size to avoid out-of-range.
    size_t last_len = (Size > 0) ? (Size / 2) : 0;
    // Reset outputs/state before second call
    minor_version = -1;
    status = 0;
    msg = nullptr;
    msg_len = 0;
    num_headers = kMaxHeaders;
    int ret2 = phr_parse_response(buf, Size, &minor_version, &status, &msg, &msg_len, headers, &num_headers, last_len);

    // Use results in a way that the compiler won't optimize calls away.
    volatile int sink = ret1 + ret2 + minor_version + status + static_cast<int>(msg_len) + static_cast<int>(num_headers);
    (void)sink;

    return 0;
}
