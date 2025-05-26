#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <curl/curl.h>
#include "vt_query.h"

#ifdef _WIN32
#include <windows.h>
#endif

#define VT_URL "https://www.virustotal.com/api/v3/files/"

struct MemoryStruct {
    char *memory;
    size_t size;
};

const char *get_api_key() {
#ifdef _WIN32
    static char buffer[512];
    DWORD len = GetEnvironmentVariableA("VT_API_KEY", buffer, sizeof(buffer));
    if (len == 0 || len >= sizeof(buffer)) return NULL;
    return buffer;
#else
    return getenv("VT_API_KEY");
#endif
}

void sha_checksum(const char *filename, const char *algo, char *outputBuffer) {
    FILE *file = NULL;

#ifdef _WIN32
    fopen_s(&file, filename, "rb");
#else
    file = fopen(filename, "rb");
#endif

    if (!file) {
        perror("File open error");
        exit(EXIT_FAILURE);
    }

    const EVP_MD *md = NULL;
    if (strcmp(algo, "sha1") == 0) {
        md = EVP_sha1();
    } else if (strcmp(algo, "sha256") == 0) {
        md = EVP_sha256();
    } else {
        fprintf(stderr, "Unsupported algorithm: %s\n", algo);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        fprintf(stderr, "EVP_MD_CTX_new failed\n");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
        fprintf(stderr, "EVP_DigestInit_ex failed\n");
        fclose(file);
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    unsigned char buf[1024];
    size_t bytesRead;
    while ((bytesRead = fread(buf, 1, sizeof(buf), file)) > 0) {
        if (EVP_DigestUpdate(mdctx, buf, bytesRead) != 1) {
            fprintf(stderr, "EVP_DigestUpdate failed\n");
            fclose(file);
            EVP_MD_CTX_free(mdctx);
            exit(EXIT_FAILURE);
        }
    }

    unsigned char hash[EVP_MAX_MD_SIZE];
    unsigned int hashLen;

    if (EVP_DigestFinal_ex(mdctx, hash, &hashLen) != 1) {
        fprintf(stderr, "EVP_DigestFinal_ex failed\n");
        fclose(file);
        EVP_MD_CTX_free(mdctx);
        exit(EXIT_FAILURE);
    }

    fclose(file);
    EVP_MD_CTX_free(mdctx);

    for (unsigned int i = 0; i < hashLen; ++i) {
        sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
    }
    outputBuffer[hashLen * 2] = '\0';
}

static size_t WriteMemoryCallback(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    struct MemoryStruct *mem = (struct MemoryStruct *)userp;

    char *ptr = realloc(mem->memory, mem->size + realsize + 1);
    if (!ptr) return 0;

    mem->memory = ptr;
    memcpy(&(mem->memory[mem->size]), contents, realsize);
    mem->size += realsize;
    mem->memory[mem->size] = '\0';

    return realsize;
}

VTResult vt_check_hash(const char *hash) {
    VTResult result = {0, 0, 0};

    const char *api_key = get_api_key();
    if (api_key == NULL || strlen(api_key) == 0) {
        fprintf(stderr, "Error: VT_API_KEY environment variable is not set.\n");
        return result;
    }

    CURL *curl;
    CURLcode res;

    struct MemoryStruct chunk = { .memory = malloc(1), .size = 0 };
    if (!chunk.memory) {
        fprintf(stderr, "Memory allocation failed.\n");
        return result;
    }

    char url[512];
    snprintf(url, sizeof(url), "%s%s", VT_URL, hash);

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Accept: application/json");

        char auth_header[512];
        snprintf(auth_header, sizeof(auth_header), "x-apikey: %s", api_key);
        headers = curl_slist_append(headers, auth_header);

        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(curl, CURLOPT_URL, url);
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteMemoryCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)&chunk);
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "curl/7.88");

        res = curl_easy_perform(curl);
        if (res == CURLE_OK) {
            const char *stats = strstr(chunk.memory, "\"last_analysis_stats\"");
            if (stats) {
                int malicious = -1, undetected = -1;
                sscanf(stats, "\"last_analysis_stats\": {\"malicious\": %d, \"suspicious\": %*d, \"undetected\": %d",
                       &malicious, &undetected);

                result.malicious_count = malicious;
                result.undetected_count = undetected;
                result.is_malicious = (malicious > 0) ? 1 : 0;
            }
        } else {
            fprintf(stderr, "curl_easy_perform() failed: %s\n", curl_easy_strerror(res));
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }

    free(chunk.memory);
    curl_global_cleanup();
    return result;
}

/*int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <file>\n", argv[0]);
        return EXIT_FAILURE;
    }

    char hash_output[65]; // Enough for SHA-256 + null terminator
    sha_checksum(argv[1], "sha1", hash_output);  // Or "sha256"
    printf("SHA1: %s\n", hash_output);

    VTResult result = vt_check_hash(hash_output);

    printf("\nVirusTotal Result:\n");
    printf("Malicious:  %d\n", result.malicious_count);
    printf("Undetected: %d\n", result.undetected_count);
    printf("Verdict: %s\n", result.is_malicious ? "MALICIOUS" : "Clean");

    return EXIT_SUCCESS;
}*/
