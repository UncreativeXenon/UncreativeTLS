/*
 ============================================================================
  XboxTLS - Lightweight TLS 1.2 Client for Xbox 360 using BearSSL
 ============================================================================
 
  Overview:
  ---------
  XboxTLS is a self-contained TLS 1.2 client implementation designed to work
  on retail or dev Xbox 360 consoles. It is built on top of BearSSL's minimal
  X.509 and SSL/TLS stack, providing secure HTTPS communication with support 
  for both RSA and EC (Elliptic Curve) trust anchors.

  The core features include:
    - Secure TLS 1.2 client using BearSSL
    - Minimal memory footprint, tuned for Xbox 360 constraints
    - Support for SHA-256, SHA-384, SHA-512, SHA-1, and SHA-224 hashes
    - X.509 certificate verification (minimal mode)
    - RSA and EC (P-256, P-384, etc.) trust anchor support
    - Works with real-world CA roots like ISRG Root X1, GTS Root R4, etc.

  Design Notes:
  -------------
  - This library is tailored for use in Xbox 360 homebrew apps and mod tools.
  - All entropy comes from XeCryptRandom (HMAC-DRBG from BearSSL).
  - Socket I/O is handled via Winsock 1.1 and raw `SOCKET` APIs.
  - Uses br_x509_minimal_context for certificate validation, not full path building.

  How to Use:
  -----------
    1. Call XboxTLS_CreateContext to initialize a TLS context.
    2. Add one or more trust anchors using XboxTLS_AddTrustAnchor_RSA or EC.
    3. Resolve the hostname and connect with XboxTLS_Connect.
    4. Use XboxTLS_Write / XboxTLS_Read to send/receive data.
    5. Call XboxTLS_Free to release memory and close the connection.
	Bonus: See ExampleClient.cpp for demonstration.
  License:
  --------
  MIT License (see LICENSE file)

  Dependencies:
  -------------
  - BearSSL (https://bearssl.org/)
  - XDK headers/libraries (e.g., xtl.h, winsockx.h)
  - Xbox 360-compatible compiler (Visual Studio 2010, Xenon SDK)
*/
#include "inc\bearssl.h"
#include <string.h>
#include <xtl.h>
#include <xboxmath.h>
#include <stdio.h>
#include <winsockx.h>
#include <winnt.h>
#include <xbox.h>
#include "Debug.h"
#include <xtl.h>
#include <stdint.h>
#include "Debug.h"
#include "XboxTLS.h"
#include "TLSClient.h"
#include "xkelib.h"
#define MAX_ANCHORS 8
#define XNCALLER_SYSAPP 2
static br_hmac_drbg_context g_drbg;

extern "C" void XeCryptRandom(BYTE* pb, DWORD cb);

// RFC 4648 Base64 Table
static const char b64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64_encode(const uint8_t *in, int in_len, char *out) {
    int i = 0, j = 0;
    for (; i < in_len;) {
        uint32_t octet_a = i < in_len ? in[i++] : 0;
        uint32_t octet_b = i < in_len ? in[i++] : 0;
        uint32_t octet_c = i < in_len ? in[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = (i > in_len + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
        out[j++] = (i > in_len)     ? '=' : b64_table[triple & 0x3F];
    }
    out[j] = '\0';
}

void generate_sec_websocket_key(char *output_key) {
    uint8_t random_bytes[16];

    XeCryptRandom(random_bytes, sizeof(random_bytes));

    base64_encode(random_bytes, sizeof(random_bytes), output_key);
}


/*
 * Custom entropy seeder for XboxTLS.
 *
 * This function provides entropy to the BearSSL HMAC-DRBG (Deterministic Random Bit Generator)
 * using the Xbox 360's internal XeCryptRandom function. It seeds the global HMAC-DRBG instance
 * `g_drbg` with a 32-byte random seed and sets the context pointer for use in TLS operations.
 *
 * Returns:
 *   1 on success (as required by BearSSL API).
 */
static int XboxTLS_CustomSeeder(const br_prng_class **ctx) {
    unsigned char seed[32];
    XeCryptRandom(seed, sizeof(seed));
    br_hmac_drbg_init(&g_drbg, &br_sha256_vtable, seed, sizeof(seed));
    *ctx = g_drbg.vtable;
    return 1;
}
br_prng_seeder
br_prng_seeder_system(const char **name) {
    if (name) *name = "XboxTLS/XeCryptRandom";
    return &XboxTLS_CustomSeeder;
}

/*
 * Internal structure representing the state of an XboxTLS connection.
 * 
 * This struct encapsulates all the necessary BearSSL components and runtime
 * information for a client-side TLS session on Xbox 360, including:
 *   - TLS client context (sc)
 *   - Minimal X.509 certificate validation context (xc)
 *   - I/O wrapper context for socket reads/writes (ioc)
 *   - Underlying socket descriptor (sock)
 *   - Array of trust anchors (certificates) for X.509 validation (anchors)
 *   - Number of valid anchors loaded (anchor_count)
 *   - Bi-directional I/O buffer (iobuf)
 */
struct XboxTLSInternal {
    br_ssl_client_context sc;
    br_x509_minimal_context xc;
    br_sslio_context ioc;
    SOCKET sock;
    br_x509_trust_anchor anchors[MAX_ANCHORS];
    int anchor_count;
    unsigned char iobuf[BR_SSL_BUFSIZE_BIDI];

    XboxTLS_LogCallback logCallback; // ✅ Per-context logger!
};

void XboxTLS_SetLogCallback(XboxTLSContext* ctx, XboxTLS_LogCallback callback) {
    if (ctx && ctx->internal) {
        XboxTLSInternal* ic = (XboxTLSInternal*)ctx->internal;
        ic->logCallback = callback;
    }
}

static void tls_log(XboxTLSContext* ctx, const char* msg) {
    if (ctx && ctx->internal) {
        XboxTLSInternal* ic = (XboxTLSInternal*)ctx->internal;
        if (ic->logCallback) {
            ic->logCallback(msg);
        }
    }
}


/*
 * Returns the BearSSL hash function vtable for a given XboxTLS hash enum.
 * 
 * This function is used to select the appropriate hash algorithm for HMAC-DRBG
 * or signature verification. It maps internal XboxTLSHash enum values to the
 * corresponding BearSSL `br_hash_class` implementations.
 *
 * Parameters:
 *   - hash: An XboxTLSHash enum value representing the desired hash algorithm.
 *
 * Returns:
 *   A pointer to the BearSSL hash vtable (br_hash_class), or NULL if unsupported.
 */
const br_hash_class* XboxTLS_GetHashVTable(XboxTLSHash hash) {
    switch (hash) {
        case XboxTLS_Hash_SHA256: return &br_sha256_vtable;
        case XboxTLS_Hash_SHA384: return &br_sha384_vtable;
        case XboxTLS_Hash_SHA512: return &br_sha512_vtable;
        case XboxTLS_Hash_SHA1:   return &br_sha1_vtable;
        case XboxTLS_Hash_SHA224: return &br_sha224_vtable;
        default: return NULL;
    }
}

/*
 * Low-level read function for BearSSL's I/O abstraction layer.
 *
 * This function is passed to BearSSL to perform socket reads.
 * It reads up to `len` bytes into `buf` from the underlying socket.
 *
 * Parameters:
 *   - ctx: Pointer to the socket (cast to void* by BearSSL)
 *   - buf: Buffer to fill with received data
 *   - len: Maximum number of bytes to read
 *
 * Returns:
 *   Number of bytes read, or a negative value on error.
 */
static int tls_socket_read(void* ctx, unsigned char* buf, size_t len) {
    SOCKET s = *(SOCKET*)ctx;
    return NetDll_recv(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), s, (char*)buf, (int)len, 0);
}

/*
 * Low-level write function for BearSSL's I/O abstraction layer.
 *
 * This function is passed to BearSSL to perform socket writes.
 * It sends `len` bytes from `buf` through the underlying socket.
 *
 * Parameters:
 *   - ctx: Pointer to the socket (cast to void* by BearSSL)
 *   - buf: Buffer containing data to send
 *   - len: Number of bytes to send
 *
 * Returns:
 *   Number of bytes written, or a negative value on error.
 */
static int tls_socket_write(void* ctx, const unsigned char* buf, size_t len) {
    SOCKET s = *(SOCKET*)ctx;
    return NetDll_send(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), s, (const char*)buf, (int)len, 0);
}





/*
 * Initializes a new XboxTLSContext and allocates internal structures.
 *
 * This function prepares a new TLS context for use in a BearSSL-based
 * Xbox TLS connection. It allocates and zeroes an internal structure that
 * will be used to manage TLS state and certificate verification.
 *
 * Parameters:
 *   - ctx: Pointer to the XboxTLSContext to initialize
 *   - hostname: Server hostname for TLS SNI (not used at this stage)
 *
 * Returns:
 *   true if initialization succeeds, false on failure (e.g., OOM or bad input).
 */
bool XboxTLS_CreateContext(XboxTLSContext* ctx, const char* hostname) {
    if (!ctx || !hostname) return false;

    XboxTLSInternal* internal = (XboxTLSInternal*)malloc(sizeof(XboxTLSInternal));
    if (!internal) return false;
    memset(internal, 0, sizeof(XboxTLSInternal));

    ctx->internal = internal;
    return true;
}


/*
 * Adds an RSA trust anchor (root certificate public key) to the XboxTLS context.
 *
 * This function appends a new X.509 trust anchor based on a raw RSA public key.
 * It manually sets up the distinguished name (DN) and the RSA key parameters
 * (modulus and exponent), and stores them in the internal anchor list.
 *
 * Parameters:
 *   - ctx: Pointer to the XboxTLSContext
 *   - dn: Distinguished name (ASN.1-encoded)
 *   - dn_len: Length of the distinguished name
 *   - n: RSA modulus (big-endian)
 *   - n_len: Length of the modulus
 *   - e: RSA public exponent (big-endian)
 *   - e_len: Length of the exponent
 *
 * Returns:
 *   true on success, false on failure (e.g. out of space, invalid input)
 */
bool XboxTLS_AddTrustAnchor_RSA(XboxTLSContext* ctx,
    const unsigned char* dn, size_t dn_len,
    const unsigned char* n, size_t n_len,
    const unsigned char* e, size_t e_len) {

    if (!ctx || !ctx->internal || dn_len == 0 || n_len == 0 || e_len == 0) return false;
    XboxTLSInternal* ic = (XboxTLSInternal*)ctx->internal;
    if (ic->anchor_count >= MAX_ANCHORS) return false;

    br_x509_trust_anchor* ta = &ic->anchors[ic->anchor_count++];
    ta->dn.data = (unsigned char*)malloc(dn_len);
    memcpy((void*)ta->dn.data, dn, dn_len);
    ta->dn.len = dn_len;
    ta->flags = BR_X509_TA_CA;

    br_rsa_public_key* key = (br_rsa_public_key*)malloc(sizeof(br_rsa_public_key));
    key->n = (unsigned char*)malloc(n_len); memcpy(key->n, n, n_len); key->nlen = n_len;
    key->e = (unsigned char*)malloc(e_len); memcpy(key->e, e, e_len); key->elen = e_len;

    ta->pkey.key_type = BR_KEYTYPE_RSA;
    ta->pkey.key.rsa = *key;

    return true;
}



/*
 * Adds an EC (Elliptic Curve) trust anchor to the XboxTLS context.
 *
 * This function appends a new X.509 trust anchor based on a raw EC public key.
 * It stores the distinguished name and curve parameters to be used for verifying
 * server certificates signed using EC keys (e.g. P-256, P-384).
 *
 * Parameters:
 *   - ctx: Pointer to the XboxTLSContext
 *   - dn: Distinguished name (ASN.1-encoded)
 *   - dn_len: Length of the distinguished name
 *   - q: Elliptic curve public point (uncompressed format)
 *   - q_len: Length of the EC point
 *   - curve_id: Identifier for the EC curve (e.g. BR_EC_secp256r1)
 *
 * Returns:
 *   true on success, false on failure (e.g. out of space, invalid input)
 */
bool XboxTLS_AddTrustAnchor_EC(XboxTLSContext* ctx,
    const unsigned char* dn, size_t dn_len,
    const unsigned char* q, size_t q_len,
    XboxTLSCurve curve_id) {

    if (!ctx || !ctx->internal || dn_len == 0 || q_len == 0) return false;
    XboxTLSInternal* ic = (XboxTLSInternal*)ctx->internal;
    if (ic->anchor_count >= MAX_ANCHORS) return false;

    br_x509_trust_anchor* ta = &ic->anchors[ic->anchor_count++];
    ta->dn.data = (unsigned char*)malloc(dn_len);
    memcpy((void*)ta->dn.data, dn, dn_len);
    ta->dn.len = dn_len;
    ta->flags = BR_X509_TA_CA;

    br_ec_public_key* key = (br_ec_public_key*)malloc(sizeof(br_ec_public_key));
    key->q = (unsigned char*)malloc(q_len); memcpy(key->q, q, q_len);
    key->qlen = q_len;
    key->curve = (int)curve_id;

    ta->pkey.key_type = BR_KEYTYPE_EC;
    ta->pkey.key.ec = *key;

    return true;
}


/*
 * Establishes a secure TLS connection using the provided XboxTLS context.
 *
 * This function creates a TCP socket to the given IP address and port, performs a TLS
 * handshake using BearSSL, and prepares the TLS engine to send and receive encrypted
 * data over the established socket. It also initializes the certificate verification
 * engine and configures the chosen hash algorithm and trust anchors.
 *
 * Parameters:
 *   - ctx: Pointer to the XboxTLSContext previously initialized by XboxTLS_CreateContext.
 *   - ip: Target server IP address (IPv4 string, e.g., "192.168.1.1").
 *   - hostname: Hostname for TLS SNI (Server Name Indication) and certificate validation.
 *   - port: TCP port to connect to (usually 443 for HTTPS).
 *
 * Returns:
 *   true on successful socket and TLS setup, false on error (e.g., invalid input,
 *   socket creation failure, connection error, invalid hash algorithm).
 *
 * Notes:
 *   - This function uses BearSSL's minimal X.509 engine.
 *   - Only one connection can be active per XboxTLSContext at a time.
 *   - Use XboxTLS_Write / XboxTLS_Read for I/O after a successful connection.
 */

bool XboxTLS_Connect(XboxTLSContext* ctx, const char* ip, const char* hostname, int port) {
    if (!ctx || !ctx->internal || !ip || !hostname) {
        tls_log(ctx, "XboxTLS_Connect: Invalid arguments.");
        debug_tls("XboxTLS_Connect: Invalid arguments.");
        return false;
    }

    XboxTLSInternal* ic = (XboxTLSInternal*)ctx->internal;

    //SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	SOCKET sock = NetDll_socket(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        tls_log(ctx, "Socket creation failed.");
        debug_tls("Socket creation failed.");
        int wsaErr = NetDll_WSAGetLastError();
        char debugBuf[64];
        sprintf(debugBuf, "WSA Error: %d", wsaErr);
        tls_log(ctx, debugBuf); debug_tls(debugBuf);
        return false;
    }

    BOOL opt_true = TRUE;
    NetDll_setsockopt(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), sock, SOL_SOCKET, 0x5801, (const char*)&opt_true, sizeof(BOOL));

    sockaddr_in sa;
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    sa.sin_addr.s_addr = inet_addr(ip);
    if (sa.sin_addr.s_addr == INADDR_NONE) {
        tls_log(ctx, "inet_addr failed: Invalid IP format.");
        debug_tls("inet_addr failed: Invalid IP format.");
        NetDll_closesocket(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), sock);
        return false;
    }

    if (NetDll_connect(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), sock, (struct sockaddr*)&sa, sizeof(sa)) == SOCKET_ERROR) {
        tls_log(ctx, "connect() failed.");
		debug_tls("connect() failed.");
        int wsaErr = NetDll_WSAGetLastError();
        char debugBuf[64];
        sprintf(debugBuf, "WSA Error: %d", wsaErr);
        tls_log(ctx, debugBuf); debug_tls(debugBuf);
        NetDll_closesocket(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), sock);
        return false;
    }

    ic->sock = sock;

    const br_hash_class* hash = XboxTLS_GetHashVTable(ctx->hashAlgo);
    if (!hash) {
        tls_log(ctx, "Invalid hash algorithm specified.");
        debug_tls("Invalid hash algorithm specified.");
        NetDll_closesocket(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), sock);
        return false;
    }

    br_x509_minimal_init(&ic->xc, hash, ic->anchors, ic->anchor_count);
    br_x509_minimal_set_rsa(&ic->xc, br_rsa_pkcs1_vrfy_get_default());
    br_x509_minimal_set_ecdsa(&ic->xc, br_ec_get_default(), br_ecdsa_vrfy_asn1_get_default());

    br_ssl_client_init_full(&ic->sc, &ic->xc, ic->anchors, ic->anchor_count);
    br_ssl_engine_set_buffer(&ic->sc.eng, ic->iobuf, sizeof(ic->iobuf), 1);
    br_ssl_client_reset(&ic->sc, hostname, 0);
    br_sslio_init(&ic->ioc, &ic->sc.eng, tls_socket_read, &ic->sock, tls_socket_write, &ic->sock);

    return true;
}



/*
 * Writes encrypted data over the active TLS connection.
 *
 * This function writes the provided plaintext buffer through BearSSL’s TLS engine,
 * which handles encryption and framing. It also flushes the write buffer to ensure
 * all data is transmitted immediately.
 *
 * Parameters:
 *   - ctx: Pointer to an active XboxTLSContext with a live TLS connection.
 *   - buf: Pointer to the data to send.
 *   - len: Length of the data in bytes.
 *
 * Returns:
 *   The number of bytes written on success, or -1 on failure.
 *
 * Notes:
 *   - Always flushes the stream after writing.
 *   - Uses BearSSL’s `br_sslio_write_all` and `br_sslio_flush`.
 */
int XboxTLS_Write(XboxTLSContext* ctx, const void* buf, int len) {
    if (!ctx || !ctx->internal || !buf || len <= 0) {
        tls_log(ctx, "XboxTLS_Write: Invalid arguments.");
        debug_tls("XboxTLS_Write: Invalid arguments.");
        return -1;
    }

    XboxTLSInternal* ic = (XboxTLSInternal*)ctx->internal;

	if (br_sslio_write_all(&ic->ioc, buf, len) < 0) {
		int err = br_ssl_engine_last_error(&ic->sc.eng);
		char msg[64];
		sprintf(msg, "TLS write error code: %d", err);
		tls_log(ctx, msg);
		debug_tls(msg);

		// 🔍 log WSA error too
		int wsaErr = NetDll_WSAGetLastError();
		char wsaMsg[64];
		sprintf(wsaMsg, "WSA Error: %d", wsaErr);
		tls_log(ctx, wsaMsg);
		debug_tls(wsaMsg);

		return -1;
	}

    if (br_sslio_flush(&ic->ioc) != 0) {
        int err = br_ssl_engine_last_error(&ic->sc.eng);
        char msg[64];
        sprintf(msg, "TLS flush error code: %d", err);
        tls_log(ctx, msg);
        debug_tls(msg);

		// Optional: log WSA error
        int wsaErr = NetDll_WSAGetLastError();
        char wsaBuf[64];
        sprintf(wsaBuf, "WSAGetLastError: %d", wsaErr);
        tls_log(ctx, wsaBuf);
        debug_tls(wsaBuf);

        return -1;
    }

    return len;
}


/*
 * Reads decrypted data from the active TLS connection.
 *
 * This function receives data from the TLS socket and decrypts it using BearSSL.
 * It blocks until data is available or an error occurs.
 *
 * Parameters:
 *   - ctx: Pointer to an active XboxTLSContext with a live TLS connection.
 *   - buf: Buffer to store the received plaintext data.
 *   - len: Maximum number of bytes to read into the buffer.
 *
 * Returns:
 *   The number of bytes read on success, or -1 on error.
 */
int XboxTLS_Read(XboxTLSContext* ctx, void* buf, int len) {
    if (!ctx || !ctx->internal || !buf || len <= 0) {
        tls_log(ctx, "XboxTLS_Read: Invalid arguments.");
        debug_tls("XboxTLS_Read: Invalid arguments.");
        return -1;
    }

	char msg2[128];
	sprintf(msg2, "RecvWS: Reading %llu bytes payload", len);
	//tls_log(ctx, msg2);
	debug_tls(msg2);

    XboxTLSInternal* ic = (XboxTLSInternal*)ctx->internal;

    int r = br_sslio_read(&ic->ioc, buf, len);
    if (r <= 0) {
        int err = br_ssl_engine_last_error(&ic->sc.eng);
        char msg[128];
        sprintf(msg, "TLS read failed: r=%d, br_ssl_engine_last_error=%d", r, err);
        //tls_log(ctx, msg);
		debug_tls(msg);
    }

    return r;
}


/*
 * Frees all internal memory and closes the TLS connection.
 *
 * This function shuts down the TLS socket and releases any dynamic memory
 * used by the TLS context, including trust anchors and cryptographic structures.
 *
 * Parameters:
 *   - ctx: Pointer to the XboxTLSContext to be cleaned up.
 *
 * Notes:
 *   - Safe to call even if the context is partially initialized.
 *   - After calling, the context's internal pointer is set to NULL.
 */
void XboxTLS_Free(XboxTLSContext* ctx) {
    if (!ctx || !ctx->internal) return;
    XboxTLSInternal* ic = (XboxTLSInternal*)ctx->internal;

    // Close socket if open
    if (ic->sock != INVALID_SOCKET && ic->sock != 0) {
        NetDll_closesocket(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), ic->sock);
        ic->sock = INVALID_SOCKET;
    }

    // Free trust anchors
    for (int i = 0; i < ic->anchor_count; ++i) {
        free((void*)ic->anchors[i].dn.data);
        if (ic->anchors[i].pkey.key_type == BR_KEYTYPE_RSA) {
            free(ic->anchors[i].pkey.key.rsa.n);
            free(ic->anchors[i].pkey.key.rsa.e);
        } else if (ic->anchors[i].pkey.key_type == BR_KEYTYPE_EC) {
            free(ic->anchors[i].pkey.key.ec.q);
        }
    }

    // Zero and free the internal struct
    memset(ic, 0, sizeof(XboxTLSInternal));
    free(ic);
    ctx->internal = NULL;
}

bool XboxTLS_PerformWebSocketHandshake(XboxTLSContext* ctx, const char* host, const char* path) {
	char websocket_key[25];  // 24 chars + null terminator
    generate_sec_websocket_key(websocket_key);
    char req[512];
    sprintf(req,
		"GET %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Key: %s\r\n"
		"Sec-WebSocket-Version: 13\r\n\r\n",
    path, host, websocket_key);

    XboxTLS_Write(ctx, req, (int)strlen(req));

    char resp[1024];
    int len = XboxTLS_Read(ctx, resp, sizeof(resp) - 1);
    if (len <= 0) return false;
    resp[len] = '\0';

    return strstr(resp, "101 Switching Protocols") != NULL;
}

static inline uint64_t to_be64(uint64_t x) {
    return ((x & 0xFFULL) << 56) |
           ((x & 0xFF00ULL) << 40) |
           ((x & 0xFF0000ULL) << 24) |
           ((x & 0xFF000000ULL) << 8) |
           ((x >> 8)  & 0xFF000000ULL) |
           ((x >> 24) & 0xFF0000ULL) |
           ((x >> 40) & 0xFF00ULL) |
           ((x >> 56) & 0xFFULL);
}

/* ... existing XboxTLS.cpp content ... */

/*
 * Performs a WebSocket upgrade request over an existing TLS connection.
 */
bool XboxTLS_WebSocketUpgrade(XboxTLSContext* ctx, const char* host, const char* path, const char* origin) {
    if (!ctx || !ctx->internal || !host || !path) return false;

    char websocket_key[25];  // 24 chars + null terminator
    generate_sec_websocket_key(websocket_key);
    char request[512];
    sprintf(request,
		"GET %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Upgrade: websocket\r\n"
		"Connection: Upgrade\r\n"
		"Sec-WebSocket-Version: 13\r\n"
		"Sec-WebSocket-Key: %s\r\n"
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64)\r\n"
		"Origin: %s\r\n"
		"Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n"
		"\r\n",
    path, host, websocket_key, origin);

    int sent = XboxTLS_Write(ctx, request, (int)strlen(request));
    if (sent <= 0) return false;

    char response[1024] = { 0 };
    int r = XboxTLS_Read(ctx, response, sizeof(response) - 1);
    if (r <= 0 || !strstr(response, "101 Switching Protocols")) return false;

    return true;
}

/*
 * Sends a WebSocket text frame (unmasked).
 */
bool XboxTLS_SendWebSocketFrame(XboxTLSContext* ctx, const void* data, size_t len) {
    if (len > 65535) return false;

    uint8_t header[10];
    size_t i = 0;

    header[i++] = 0x81; // FIN bit set, text frame

    if (len <= 125) {
        header[i++] = 0x80 | (uint8_t)len;
    } else {
        header[i++] = 0x80 | 126;
        header[i++] = (len >> 8) & 0xFF;
        header[i++] = len & 0xFF;
    }

    uint8_t mask[4] = {
        static_cast<uint8_t>(rand() & 0xFF),
        static_cast<uint8_t>(rand() & 0xFF),
        static_cast<uint8_t>(rand() & 0xFF),
        static_cast<uint8_t>(rand() & 0xFF)
    };
    memcpy(&header[i], mask, 4);
    i += 4;

    size_t total_len = i + len;
    uint8_t* frame = new uint8_t[total_len];

    memcpy(frame, header, i);

    const uint8_t* data_bytes = static_cast<const uint8_t*>(data);
    for (size_t j = 0; j < len; ++j) {
        frame[i + j] = data_bytes[j] ^ mask[j % 4];
    }

    XboxTLS_Write(ctx, frame, static_cast<int>(total_len));
    delete[] frame;

    return true;
}

/*
 * Receives a WebSocket text frame (unmasked, synchronous read).
 * Caller must free the returned buffer.
 */
char* XboxTLS_ReceiveWebSocketFrame(XboxTLSContext* ctx, size_t* outLen, bool* isZlib) {
    if (!ctx || !ctx->internal || !outLen || !isZlib) return NULL;

    *isZlib = false;

    unsigned char header[10];
    if (XboxTLS_Read(ctx, header, 2) < 2) return NULL;

    size_t len = header[1] & 0x7F;

    if (len == 126) {
        if (XboxTLS_Read(ctx, header + 2, 2) < 2) return NULL;
        len = (header[2] << 8) | header[3];
    } else if (len == 127) {
        unsigned char extendedLen[8];
        if (XboxTLS_Read(ctx, extendedLen, 8) < 8) return NULL;

        len = 0;
        for (int i = 0; i < 8; ++i) {
            len = (len << 8) | extendedLen[i];
        }

        if (len > 6071080) {
            tls_log(ctx, "Payload exceeds 6MB limit — assuming zlib, not returning payload.");
            debug_tls("Payload exceeds 6MB limit — assuming zlib, not returning payload.");
            *isZlib = true;
            *outLen = len;
            return NULL; // ⬅️ don't return the payload if it's zlib
        }
    }

    char* payload = (char*)malloc(len + 1);
    if (!payload) {
        tls_log(ctx, "Failed to allocate memory for payload.");
        debug_tls("Failed to allocate memory for payload.");
        return NULL;
    }

    int totalRead = 0;
    while (totalRead < (int)len) {
        int r = XboxTLS_Read(ctx, payload + totalRead, (int)(len - totalRead));
        if (r <= 0) {
            free(payload);
            return NULL;
        }
        totalRead += r;
    }

    payload[len] = '\0';
    *outLen = len;
    return payload;
}

bool XboxTLS_IsAlive(XboxTLSContext* ctx) {
    if (!ctx || !ctx->internal) return false;
    XboxTLSInternal* ic = (XboxTLSInternal*)ctx->internal;
    return ic->sock != INVALID_SOCKET && ic->sock != 0;
}

bool XboxTLS_HasFatalError(XboxTLSContext* ctx) {
    if (!ctx || !ctx->internal) return true;
    XboxTLSInternal* ic = (XboxTLSInternal*)ctx->internal;
    return br_ssl_engine_last_error(&ic->sc.eng) != 0;
}

bool XboxTLS_SocketDead(XboxTLSContext* ctx) {
    if (!ctx || !ctx->internal) return true;
    XboxTLSInternal* ic = (XboxTLSInternal*)ctx->internal;

    fd_set errSet;
    timeval timeout = { 0, 0 };

    FD_ZERO(&errSet);
    FD_SET(ic->sock, &errSet);

    int result = NetDll_select(static_cast<XNCALLER_TYPE>(XNCALLER_SYSAPP), ic->sock + 1, NULL, NULL, &errSet, &timeout);
    return (result > 0 && FD_ISSET(ic->sock, &errSet));
}
