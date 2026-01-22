#include <cstdint>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <cassert>
#include <string>
#include <vector>

extern "C" {
	// Include the internal mosquitto struct definition so we can allocate and populate it.
	// The path below matches the repository layout observed; adjust if needed.
#include "/src/mosquitto/lib/mosquitto_internal.h"

	// Avoid redefinition of _GNU_SOURCE: if the build system or compiler already
	// defined it, undefine it so net_mosq.c can define it without causing a
	// -Werror,-Wmacro-redefined error.
#ifdef _GNU_SOURCE
#undef _GNU_SOURCE
#endif

	// Forward-declare OpenSSL types and the original SSL_get_ex_data so we can
	// provide a small wrapper that casts its void* return to struct mosquitto*.
	// We use a wrapper function + macro trick: define the wrapper first (so the
	// wrapper body uses the original symbol), then define a macro that maps
	// calls in net_mosq.c to the wrapper (so all calls inside net_mosq.c will
	// receive the proper typed pointer).
	typedef struct ssl_st SSL;
	void *SSL_get_ex_data(const SSL *ssl, int idx);
	static inline struct mosquitto *SSL_get_ex_data_mosq(const SSL *ssl, int idx) {
		return (struct mosquitto *)SSL_get_ex_data(ssl, idx);
	}
	// After the wrapper is defined, map SSL_get_ex_data to the wrapper for the
	// translation unit that will include net_mosq.c. This ensures assignments
	// like `mosq = SSL_get_ex_data(ssl, idx);` compile under C++.
#define SSL_get_ex_data(ssl, idx) SSL_get_ex_data_mosq(ssl, idx)

	// Forward-declare SSL_CTX and its free function so the harness can free
	// any SSL_CTX that net__init_ssl_ctx allocated. This prevents unbounded
	// memory growth across fuzzer iterations.
	typedef struct ssl_ctx_st SSL_CTX;
	void SSL_CTX_free(SSL_CTX *ctx);

	// Include the implementation of the target function so the static function
	// net__init_ssl_ctx (which is file-local in net_mosq.c) is available in this
	// translation unit and can be called directly by the harness.
	// Wrapping the include in extern "C" ensures the included C symbols use C linkage.
#include "/src/mosquitto/lib/net_mosq.c"
}

static char *make_string_from_bytes(const uint8_t *data, size_t len) {
	// ensure room for NUL
	char *s = (char *)malloc(len + 1);
	if(!s) return nullptr;
	if(len && data) memcpy(s, data, len);
	s[len] = '\0';
	return s;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
	if(!Data || Size == 0) return 0;

	// Create a zeroed mosquitto instance.
	struct mosquitto *mosq = (struct mosquitto *)calloc(1, sizeof(struct mosquitto));
	if(!mosq) return 0;

	// We'll consume the input sequentially. Protect bounds.
	size_t pos = 0;

	auto remain = [&]() { return (Size > pos) ? (Size - pos) : 0; };

	// Read a control byte (if available) to select which fields to set.
	uint8_t control = 0;
	if(remain() >= 1) {
		control = Data[pos++];
	}

	// Bits in control:
	// bit0 -> set tls_cafile
	// bit1 -> set tls_capath
	// bit2 -> set tls_certfile
	// bit3 -> set tls_keyfile
	// bit4 -> set tls_alpn
	// bit5 -> set tls_version
	// bit6 -> set tls_ciphers
	// bit7 -> set tls_13_ciphers
	//
	// For each selected field, we read a length byte (if available) then that many bytes.
	auto read_string_field = [&](char **dest) {
		if(remain() < 1) return;
		uint8_t l = Data[pos++];
		size_t len = (size_t)l;
		if(len > remain()) len = remain();
		if(len == 0) {
			// set to empty string
			*dest = make_string_from_bytes(nullptr, 0);
		} else {
			*dest = make_string_from_bytes(Data + pos, len);
			pos += len;
		}
	};

	if(control & 0x01) read_string_field(&mosq->tls_cafile);
	if(control & 0x02) read_string_field(&mosq->tls_capath);
	if(control & 0x04) read_string_field(&mosq->tls_certfile);
	if(control & 0x08) read_string_field(&mosq->tls_keyfile);
	if(control & 0x10) read_string_field(&mosq->tls_alpn);
	if(control & 0x20) read_string_field(&mosq->tls_version);
	if(control & 0x40) read_string_field(&mosq->tls_ciphers);
	if(control & 0x80) read_string_field(&mosq->tls_13_ciphers);

	// Next byte (if any) controls some boolean flags and small enums.
	if(remain() >= 1) {
		uint8_t b = Data[pos++];
		// bit0 -> tls_psk (presence)
		// bit1 -> tls_use_os_certs
		// bit2 -> tls_cert_reqs = 0 or 1
		// bits3-4 -> tls_keyform (0 = default, 1 = mosq_k_engine if available)
		if(b & 0x01) {
			// Set a small PSK string if requested. This allocates memory that we will free later.
			mosq->tls_psk = make_string_from_bytes((const uint8_t *)"psk", 3);
			// Optionally set a PSK identity too.
			mosq->tls_psk_identity = make_string_from_bytes((const uint8_t *)"id", 2);
		} else {
			mosq->tls_psk = nullptr;
			mosq->tls_psk_identity = nullptr;
		}
		mosq->tls_use_os_certs = (b & 0x02) ? true : false;
		mosq->tls_cert_reqs = (b & 0x04) ? 1 : 0;
		uint8_t keyform_sel = (b >> 3) & 0x03;
		if(keyform_sel == 1) {
			// prefer engine keyform if defined in build; if the symbol isn't present
			// it will fallback to numeric value 1 which may or may not match.
		#ifdef mosq_k_engine
			mosq->tls_keyform = (enum mosquitto__keyform)mosq_k_engine;
		#else
			mosq->tls_keyform = (enum mosquitto__keyform)1;
		#endif
		} else {
			mosq->tls_keyform = (enum mosquitto__keyform)0;
		}
	}

	// If there's remaining bytes, make a small hostname to pass if needed by callers (not used by net__init_ssl_ctx)
	char *dummy_host = nullptr;
	if(remain() >= 1) {
		uint8_t l = Data[pos++];
		size_t len = (size_t)l;
		if(len > remain()) len = remain();
		dummy_host = make_string_from_bytes(Data + pos, len);
		pos += len;
	} else {
		dummy_host = make_string_from_bytes((const uint8_t *)"localhost", 9);
	}

	// To reduce the chance of entering engine-specific code paths that require
	// additional global setup, zero fields we don't intend to use.
	mosq->ssl = nullptr;
	mosq->ssl_ctx = nullptr;
#ifndef WITH_BROKER
	mosq->user_ssl_ctx = nullptr;
#endif

	// The function under test will call net__init_tls(); ensure mosq structure is somewhat sane.
	// Call the target function. Wrap in a try/catch to avoid C++ exceptions leaking (the target is C).
	int rc = 0;
	// Some builds may require additional global initialization; we call the function directly.
	rc = net__init_ssl_ctx(mosq);

	// Free allocated strings in mosq. Many fields may be NULL.
	auto free_if = [&](char *p) { if(p) { free(p); } };
	free_if(mosq->tls_cafile);
	free_if(mosq->tls_capath);
	free_if(mosq->tls_certfile);
	free_if(mosq->tls_keyfile);
	free_if(mosq->tls_alpn);
	free_if(mosq->tls_version);
	free_if(mosq->tls_ciphers);
	free_if(mosq->tls_13_ciphers);

	// Also free PSK related fields we allocated above (if any).
	free_if(mosq->tls_psk);
	free_if(mosq->tls_psk_identity);

	free_if(dummy_host);

	// If net__init_ssl_ctx allocated an SSL_CTX and stored it in mosq->ssl_ctx,
	// free it here to avoid unbounded memory growth across fuzzer inputs.
	if(mosq->ssl_ctx) {
		SSL_CTX_free((SSL_CTX *)mosq->ssl_ctx);
		mosq->ssl_ctx = nullptr;
	}

	// Free mosq structure
	free(mosq);

	(void)rc; // silence unused variable warnings in some builds
	return 0;
}
