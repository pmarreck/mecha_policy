#ifndef MECHA_POLICY_H
#define MECHA_POLICY_H

#include <stddef.h>
#include <stdint.h>

/* The shared Mecha entitlement decision codes (contract rev 1.1).
 * 1 (no_license) and 2 (not_authentic) belong to layers upstream of
 * mecha_policy_decide -- the app's store and sigil's verifier -- and are
 * never returned by it; they are defined here so every surface (gate,
 * `license status` JSON, About) speaks one enum. */
enum {
	MECHA_POLICY_AUTHORIZED = 0,
	MECHA_POLICY_NO_LICENSE = 1,
	MECHA_POLICY_NOT_AUTHENTIC = 2,
	MECHA_POLICY_MALFORMED = 3,
	MECHA_POLICY_WRONG_PRODUCT = 4,
	MECHA_POLICY_EXPIRED = 5,
	MECHA_POLICY_VERSION_CEILING = 6,
	MECHA_POLICY_CLASS_KEY_MISMATCH = 7,
	MECHA_POLICY_CLOCK_ROLLBACK = 8,
	MECHA_POLICY_OPERATION_NOT_GRANTED = 9,
};

/* Which trust role's public key verified the envelope. */
enum {
	MECHA_POLICY_ROLE_BETA_LICENSE = 0,
	MECHA_POLICY_ROLE_PAID_LICENSE = 1,
};

/* Evaluate one sigil-VERIFIED payload against one admission request.
 * payload must be the exact bytes sigil returned; dates are YYYY-MM-DD in
 * UTC; clock_high_water and operation may be NULL. Returns a decision code
 * (>= 0), or a negative value: -1 bad role, -2 invalid now date, -3
 * allocation failure. Negative values are caller bugs or resource
 * exhaustion, never license verdicts. */
int32_t mecha_policy_decide(
	const uint8_t *payload_ptr,
	size_t payload_len,
	uint8_t role,
	const char *product,
	uint32_t app_major,
	const char *now_utc_date,
	const char *clock_high_water,
	const char *operation);

/* Stable name for a decision code, for status surfaces and logs. */
const char *mecha_policy_reason_name(uint8_t code);

/* The ABI contract version this header describes; assert it at startup. */
uint32_t mecha_policy_abi_version(void);

const char *mecha_policy_version(void);

/* Installation certificates (sigil contract section 15). Additive to ABI 1. */
enum {
	MECHA_POLICY_INSTALL_CERT_VALID = 0,
	MECHA_POLICY_INSTALL_CERT_MALFORMED = 1,
	MECHA_POLICY_INSTALL_CERT_WRONG_PRODUCT = 2,
	MECHA_POLICY_INSTALL_CERT_OTHER_MACHINE = 3,
	MECHA_POLICY_INSTALL_CERT_OTHER_LICENSE = 4,
	MECHA_POLICY_INSTALL_CERT_EXPIRED = 5,
	MECHA_POLICY_INSTALL_CERT_CLOCK_ROLLBACK = 6,
};

/* Decide whether a sigil-VERIFIED installation certificate admits this
 * machine under this license. license_sha256 is the lowercase hex SHA-256
 * of the exact imported license envelope bytes; machine is the value from
 * mecha_policy_machine_hash. Returns a code (>= 0), or -1 malformed hash
 * argument, -2 invalid now date, -3 allocation failure. */
int32_t mecha_policy_install_decide(
	const uint8_t *cert_ptr,
	size_t cert_len,
	const char *product,
	const char *license_sha256,
	const char *machine,
	const char *now_utc_date,
	const char *clock_high_water);

const char *mecha_policy_install_reason_name(uint8_t code);

/* The per-product machine fingerprint: SHA-256 over "mecha-install-v1" ||
 * product || 0x00 || raw id (trimmed of ASCII whitespace, ASCII-lowercased),
 * written as 64 lowercase hex characters plus a NUL into out_65. The raw id
 * never needs to leave the machine. */
void mecha_policy_machine_hash(const char *product, const uint8_t *raw_id, size_t raw_len, char *out_65);

#endif
