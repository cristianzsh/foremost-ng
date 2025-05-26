#ifndef VT_QUERY_H
#define VT_QUERY_H

#ifdef __cplusplus
extern "C" {
#endif

// Structure to hold VirusTotal scan result
typedef struct {
    int is_malicious;       // 1 if malicious > 0, else 0
    int malicious_count;    // number of engines that flagged as malicious
    int undetected_count;   // number of engines that marked it undetected
} VTResult;

// Computes a checksum (SHA-1, SHA-256, etc.)
void sha_checksum(const char *filename, const char *algo, char *outputBuffer);

// Queries VirusTotal using a given SHA-1/SHA-256 hash
VTResult vt_check_hash(const char *hash);

#ifdef __cplusplus
}
#endif

#endif // VT_QUERY_H
