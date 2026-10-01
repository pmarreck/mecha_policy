/* mecha-policy: the policy core's dogfooding CLI. All I/O lives here; the
 * decision itself is the same mecha_policy_decide every app gate calls.
 *
 *   mecha-policy decide --payload FILE --role beta-license|paid-license \
 *     --product ID --app-major N --now YYYY-MM-DD [--hwm YYYY-MM-DD] \
 *     [--operation OP]
 *
 * Prints the reason name to stdout. Exit: 0 authorized, 1 refused,
 * 64 usage, 66 missing input, 70 internal. Later arguments override
 * earlier ones; '-' or '@stdin' reads the payload from stdin. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "mecha_policy.h"

#define EX_USAGE 64
#define EX_NOINPUT 66
#define EX_SOFTWARE 70

static unsigned char *slurp(FILE *f, size_t *len_out) {
	size_t cap = 4096, n = 0;
	unsigned char *buf = malloc(cap);
	if (!buf) return NULL;
	for (;;) {
		if (n == cap) {
			cap *= 2;
			unsigned char *nb = realloc(buf, cap);
			if (!nb) { free(buf); return NULL; }
			buf = nb;
		}
		size_t got = fread(buf + n, 1, cap - n, f);
		n += got;
		if (got == 0) break;
	}
	if (ferror(f)) { free(buf); return NULL; }
	*len_out = n;
	return buf;
}

static void usage(FILE *out) {
	fprintf(out,
	    "Usage: mecha-policy decide --payload FILE --role beta-license|paid-license\n"
	    "         --product ID --app-major N --now YYYY-MM-DD\n"
	    "         [--hwm YYYY-MM-DD] [--operation OP]\n"
	    "       mecha-policy install --cert FILE --product ID --license-sha256 HEX\n"
	    "         --machine HEX --now YYYY-MM-DD [--hwm YYYY-MM-DD]\n"
	    "       mecha-policy machine-hash --product ID --raw-id-file FILE\n"
	    "       mecha-policy --help | --about\n");
}

/* `install`: decide an installation certificate. `machine-hash`: print the
 * per-product fingerprint of a raw machine id read from a file or stdin. */
static int cmd_install(int argc, char *argv[]) {
	const char *cert_path = NULL, *product = NULL, *lic = NULL, *machine = NULL, *now = NULL, *hwm = NULL;
	for (int i = 2; i < argc; i++) {
		const char *a = argv[i];
		if (i + 1 < argc) {
			if (strcmp(a, "--cert") == 0) { cert_path = argv[++i]; continue; }
			if (strcmp(a, "--product") == 0) { product = argv[++i]; continue; }
			if (strcmp(a, "--license-sha256") == 0) { lic = argv[++i]; continue; }
			if (strcmp(a, "--machine") == 0) { machine = argv[++i]; continue; }
			if (strcmp(a, "--now") == 0) { now = argv[++i]; continue; }
			if (strcmp(a, "--hwm") == 0) { hwm = argv[++i]; continue; }
		}
		fprintf(stderr, "mecha-policy: unknown or incomplete argument: %s\n", a);
		usage(stderr);
		return EX_USAGE;
	}
	if (!cert_path || !product || !lic || !machine || !now) { usage(stderr); return EX_USAGE; }
	FILE *in = (strcmp(cert_path, "-") == 0 || strcmp(cert_path, "@stdin") == 0) ? stdin : fopen(cert_path, "rb");
	if (!in) { fprintf(stderr, "mecha-policy: cannot open %s\n", cert_path); return EX_NOINPUT; }
	size_t len = 0;
	unsigned char *cert = slurp(in, &len);
	if (in != stdin) fclose(in);
	if (!cert) { fprintf(stderr, "mecha-policy: read failed\n"); return EX_SOFTWARE; }
	int32_t rc = mecha_policy_install_decide(cert, len, product, lic, machine, now, hwm);
	free(cert);
	if (rc < 0) {
		fprintf(stderr, "mecha-policy: %s\n", rc == -2 ? "invalid --now date (want YYYY-MM-DD)" :
		    rc == -1 ? "--license-sha256 and --machine must be 64 lowercase hex characters" : "internal error");
		return rc == -3 ? EX_SOFTWARE : EX_USAGE;
	}
	printf("%s\n", mecha_policy_install_reason_name((uint8_t)rc));
	return rc == MECHA_POLICY_INSTALL_CERT_VALID ? 0 : 1;
}

static int cmd_machine_hash(int argc, char *argv[]) {
	const char *product = NULL, *raw_path = NULL;
	for (int i = 2; i < argc; i++) {
		const char *a = argv[i];
		if (i + 1 < argc) {
			if (strcmp(a, "--product") == 0) { product = argv[++i]; continue; }
			if (strcmp(a, "--raw-id-file") == 0) { raw_path = argv[++i]; continue; }
		}
		fprintf(stderr, "mecha-policy: unknown or incomplete argument: %s\n", a);
		usage(stderr);
		return EX_USAGE;
	}
	if (!product || !raw_path) { usage(stderr); return EX_USAGE; }
	FILE *in = (strcmp(raw_path, "-") == 0 || strcmp(raw_path, "@stdin") == 0) ? stdin : fopen(raw_path, "rb");
	if (!in) { fprintf(stderr, "mecha-policy: cannot open %s\n", raw_path); return EX_NOINPUT; }
	size_t len = 0;
	unsigned char *raw = slurp(in, &len);
	if (in != stdin) fclose(in);
	if (!raw) { fprintf(stderr, "mecha-policy: read failed\n"); return EX_SOFTWARE; }
	char out[65];
	mecha_policy_machine_hash(product, raw, len, out);
	free(raw);
	printf("%s\n", out);
	return 0;
}

int main(int argc, char *argv[]) {
	if (argc >= 2 && strcmp(argv[1], "install") == 0) return cmd_install(argc, argv);
	if (argc >= 2 && strcmp(argv[1], "machine-hash") == 0) return cmd_machine_hash(argc, argv);
	const char *payload_path = NULL, *role_s = NULL, *product = NULL;
	const char *now = NULL, *hwm = NULL, *operation = NULL;
	long app_major = -1;
	int saw_decide = 0;

	for (int i = 1; i < argc; i++) {
		const char *a = argv[i];
		if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0 || strcmp(a, "/h") == 0) {
			usage(stdout);
			return 0;
		}
		if (strcmp(a, "--about") == 0) {
			printf("mecha-policy %s -- shared Mecha license policy decisions (one implementation, every gate)\n",
			    mecha_policy_version());
			return 0;
		}
		if (strcmp(a, "decide") == 0) { saw_decide = 1; continue; }
		if (i + 1 < argc) {
			if (strcmp(a, "--payload") == 0) { payload_path = argv[++i]; continue; }
			if (strcmp(a, "--role") == 0) { role_s = argv[++i]; continue; }
			if (strcmp(a, "--product") == 0) { product = argv[++i]; continue; }
			if (strcmp(a, "--app-major") == 0) { app_major = strtol(argv[++i], NULL, 10); continue; }
			if (strcmp(a, "--now") == 0) { now = argv[++i]; continue; }
			if (strcmp(a, "--hwm") == 0) { hwm = argv[++i]; continue; }
			if (strcmp(a, "--operation") == 0) { operation = argv[++i]; continue; }
		}
		fprintf(stderr, "mecha-policy: unknown or incomplete argument: %s\n", a);
		usage(stderr);
		return EX_USAGE;
	}

	if (!saw_decide || !payload_path || !role_s || !product || app_major < 0 || !now) {
		usage(stderr);
		return EX_USAGE;
	}

	uint8_t role;
	if (strcmp(role_s, "beta-license") == 0) role = MECHA_POLICY_ROLE_BETA_LICENSE;
	else if (strcmp(role_s, "paid-license") == 0) role = MECHA_POLICY_ROLE_PAID_LICENSE;
	else {
		fprintf(stderr, "mecha-policy: unknown role: %s\n", role_s);
		return EX_USAGE;
	}

	FILE *in;
	if (strcmp(payload_path, "-") == 0 || strcmp(payload_path, "@stdin") == 0) {
		in = stdin;
	} else {
		in = fopen(payload_path, "rb");
		if (!in) {
			fprintf(stderr, "mecha-policy: cannot open %s\n", payload_path);
			return EX_NOINPUT;
		}
	}
	size_t len = 0;
	unsigned char *payload = slurp(in, &len);
	if (in != stdin) fclose(in);
	if (!payload) {
		fprintf(stderr, "mecha-policy: read failed\n");
		return EX_SOFTWARE;
	}

	int32_t rc = mecha_policy_decide(payload, len, role, product,
	    (uint32_t)app_major, now, hwm, operation);
	free(payload);

	if (rc < 0) {
		fprintf(stderr, "mecha-policy: %s\n",
		    rc == -2 ? "invalid --now date (want YYYY-MM-DD)" : "internal error");
		return rc == -2 ? EX_USAGE : EX_SOFTWARE;
	}
	printf("%s\n", mecha_policy_reason_name((uint8_t)rc));
	return rc == MECHA_POLICY_AUTHORIZED ? 0 : 1;
}
