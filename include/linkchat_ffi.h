#ifndef LINKCHAT_FFI_H
#define LINKCHAT_FFI_H

#include <stddef.h>
#include <stdint.h>

#define LC_OK 0
#define LC_ERR_NULL_POINTER 1
#define LC_ERR_INVALID_LENGTH 2
#define LC_ERR_INVALID_HANDLE 3
#define LC_ERR_WIRE 4
#define LC_ERR_NON_CANONICAL 5
#define LC_ERR_BUFFER_TOO_SMALL 6
#define LC_ERR_INTERNAL 7
#define LC_ERR_CRYPTO 8
#define LC_ERR_REJECTED 9
#define LC_ERR_STORAGE 10
#define LC_ERR_RETRYABLE 11
#define LC_ERR_INVALID_ARGUMENT 12
#define LC_ERR_NOT_READY 13

typedef struct LinkChatPackageMetadata {
    uint16_t protocol_major;
    uint16_t protocol_minor;
    uint16_t cipher_suite;
    uint64_t session_id;
    uint64_t turn;
    uint64_t generation;
    uint64_t key_id;
    uint64_t expiration;
    uint8_t x25519_public_key[32];
    uint32_t mlkem_public_key_len;
    uint32_t package_auth_len;
} LinkChatPackageMetadata;

typedef struct LinkChatEndpointMetadata {
    uint64_t session_id;
    uint8_t endpoint;
    uint8_t reserved[7];
    uint64_t turn;
    uint64_t consumed_message_count;
    uint8_t local_identity_public[32];
    uint8_t peer_identity_public[32];
    uint64_t local_generation;
    uint64_t local_key_id;
    uint64_t local_expiration;
    uint8_t local_x25519_public_key[32];
    uint32_t local_mlkem_public_key_len;
    uint32_t local_package_auth_len;
    uint64_t peer_generation;
    uint64_t peer_key_id;
    uint64_t peer_expiration;
    uint8_t peer_x25519_public_key[32];
    uint32_t peer_mlkem_public_key_len;
    uint32_t peer_package_auth_len;
} LinkChatEndpointMetadata;

typedef struct LinkChatReceiveMetadata {
    uint64_t message_id;
    size_t payload_len;
    size_t returned_package_len;
} LinkChatReceiveMetadata;

int32_t linkchat_session_create(uint64_t session_id, uint64_t *out_handle);
int32_t linkchat_session_destroy(uint64_t handle);
int32_t linkchat_session_id(uint64_t handle, uint64_t *out_session_id);

int32_t linkchat_package_open(const uint8_t *input, size_t input_len, uint64_t *out_handle);
int32_t linkchat_package_destroy(uint64_t handle);
int32_t linkchat_package_encoded_len(uint64_t handle, size_t *out_len);
int32_t linkchat_package_write(uint64_t handle, uint8_t *out, size_t capacity, size_t *written);
int32_t linkchat_package_metadata(uint64_t handle, LinkChatPackageMetadata *out);

int32_t linkchat_bootstrap_create(
    uint64_t session_id,
    uint8_t endpoint,
    const uint8_t *bootstrap_previous_hash,
    uint64_t expiration,
    uint64_t now,
    uint64_t *out_handle);
int32_t linkchat_bootstrap_destroy(uint64_t handle);
int32_t linkchat_bootstrap_identity_write(
    uint64_t handle,
    uint8_t *out,
    size_t capacity,
    size_t *written);
int32_t linkchat_bootstrap_package_encoded_len(uint64_t handle, size_t *out_len);
int32_t linkchat_bootstrap_package_write(
    uint64_t handle,
    uint8_t *out,
    size_t capacity,
    size_t *written);

int32_t linkchat_endpoint_create(
    uint64_t session_id,
    uint8_t endpoint,
    const uint8_t *peer_identity,
    const uint8_t *bootstrap_previous_hash,
    const uint8_t *peer_package,
    size_t peer_package_len,
    uint64_t expiration,
    uint64_t now,
    uint64_t *out_handle);
int32_t linkchat_endpoint_create_from_bootstrap(
    uint64_t bootstrap_handle,
    const uint8_t *peer_identity,
    const uint8_t *peer_package,
    size_t peer_package_len,
    uint64_t *out_handle);
int32_t linkchat_endpoint_destroy(uint64_t handle);
int32_t linkchat_endpoint_metadata(uint64_t handle, LinkChatEndpointMetadata *out);
int32_t linkchat_endpoint_package_encoded_len(uint64_t handle, size_t *out_len);
int32_t linkchat_endpoint_package_write(
    uint64_t handle,
    uint8_t *out,
    size_t capacity,
    size_t *written);
int32_t linkchat_endpoint_send_prepare(
    uint64_t endpoint_handle,
    uint64_t message_id,
    const uint8_t *payload,
    size_t payload_len,
    uint64_t now,
    uint8_t *out_envelope,
    size_t envelope_capacity,
    size_t *out_written,
    uint64_t *out_prepare_handle);
int32_t linkchat_endpoint_send_commit(uint64_t prepare_handle);
int32_t linkchat_endpoint_receive_prepare(
    uint64_t endpoint_handle,
    const uint8_t *envelope,
    size_t envelope_len,
    uint64_t now,
    uint64_t next_expiration,
    uint64_t *out_prepare_handle);
int32_t linkchat_endpoint_receive_commit(
    uint64_t prepare_handle,
    uint8_t *payload_out,
    size_t payload_capacity,
    size_t *payload_written,
    uint8_t *package_out,
    size_t package_capacity,
    size_t *package_written,
    LinkChatReceiveMetadata *metadata_out);
int32_t linkchat_endpoint_recover(uint64_t handle);

#endif
