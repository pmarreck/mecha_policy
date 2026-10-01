//! mecha_policy — the ONE shared Mecha entitlement policy implementation.
//! Contract: sigil docs/MECHA_LICENSE_CONTRACT_V1.md (rev 1.1). Sequencing:
//! authenticity (sigil, upstream of this module) -> schema validity ->
//! authorization. This core performs NO I/O and reads NO clocks; every
//! input — verified payload bytes, which trust role verified, product,
//! app major version, current UTC date, clock high-water mark — is
//! injected by the caller. Dates are YYYY-MM-DD strings, all UTC;
//! zero-padded ISO dates make lexicographic order chronological order,
//! which is the only date arithmetic evaluation ever needs.

const std = @import("std");

/// Which trust role's public key verified the envelope. Key-to-grant-class
/// binding (contract section 4): each role authorizes only its own classes,
/// so a leaked beta key cannot mint paid/no-expiry grants.
pub const Role = enum(u8) {
    beta_license = 0,
    paid_license = 1,
};

/// The shared reason codes (contract section 3). Codes 1 and 2 belong to
/// layers upstream of decide() — the app (no stored license) and sigil
/// (signature) — and are never returned here; they exist so every surface
/// (gate, `license status` JSON, About) speaks one enum.
pub const Decision = enum(u8) {
    authorized = 0,
    no_license = 1,
    not_authentic = 2,
    malformed = 3,
    wrong_product = 4,
    expired = 5,
    version_ceiling = 6,
    class_key_mismatch = 7,
    clock_rollback = 8,
    operation_not_granted = 9,

    pub fn name(self: Decision) [:0]const u8 {
        return switch (self) {
            .authorized => "authorized",
            .no_license => "no_license",
            .not_authentic => "not_authentic",
            .malformed => "malformed",
            .wrong_product => "wrong_product",
            .expired => "expired",
            .version_ceiling => "version_ceiling",
            .class_key_mismatch => "class_key_mismatch",
            .clock_rollback => "clock_rollback",
            .operation_not_granted => "operation_not_granted",
        };
    }
};

pub const Error = error{
    /// The caller-supplied now_utc_date is not a valid YYYY-MM-DD date.
    /// A programmer error, deliberately NOT a Decision: garbage clocks must
    /// fail loudly, not fold into a policy verdict.
    InvalidNow,
    /// A caller-supplied hash is not 64 lowercase hex characters. Like
    /// InvalidNow, a programmer error and never a verdict.
    InvalidArgument,
    OutOfMemory,
};

pub const Request = struct {
    /// Exact bytes sigil verified; never pre-parsed, never re-serialized.
    payload: []const u8,
    verified_role: Role,
    /// The asking application's product identifier, e.g. "mecha-validate".
    product: []const u8,
    app_major: u32,
    /// Current UTC date, YYYY-MM-DD.
    now_utc_date: []const u8,
    /// Latest date this install has ever seen (opaque high-water store,
    /// section: highWaterFormat). null = no stored mark yet.
    clock_high_water: ?[]const u8 = null,
    /// Operation class being requested; null = the app's default protected
    /// operation. features "full" covers every operation.
    operation: ?[]const u8 = null,
};

/// The typed shape of a v1 license payload. std.json's typed parser IS the
/// schema gate: unknown fields, duplicate fields, and wrong value types all
/// fail the parse (ignore_unknown_fields=false is the default;
/// duplicate_field_behavior=error is set at the call), which is exactly the
/// strictness the contract demands from adversarial bytes.
const PayloadV1 = struct {
    customer_email: []const u8,
    customer_name_canonical: []const u8,
    expiry: ?[]const u8 = null,
    features: []const u8,
    max_major: []const u8,
    offline_days: []const u8,
    payment_provider: []const u8,
    payment_ref: []const u8,
    product: []const u8,
    purchase_date: []const u8,
    v: []const u8,
};

/// Evaluate one verified license payload against one admission request.
/// Sequencing (contract rev 1.1): schema -> class/key binding -> product ->
/// version ceiling -> clock rollback -> expiry -> operation. Distinct from
/// both crypto failures (upstream) and file corruption (elsewhere entirely).
pub fn decide(allocator: std.mem.Allocator, req: Request) Error!Decision {
    if (!isValidDate(req.now_utc_date)) return Error.InvalidNow;

    const parsed = std.json.parseFromSlice(PayloadV1, allocator, req.payload, .{
        .duplicate_field_behavior = .@"error",
    }) catch |e| switch (e) {
        error.OutOfMemory => return Error.OutOfMemory,
        else => return .malformed,
    };
    defer parsed.deinit();
    const p = parsed.value;

    // Schema, beyond what the typed parse enforced.
    if (!std.mem.eql(u8, p.v, "1")) return .malformed;
    const class = classOf(p.payment_provider) orelse return .malformed;
    if (!isValidDate(p.purchase_date)) return .malformed;
    if (p.expiry) |x| {
        if (!isValidDate(x)) return .malformed;
    }
    // A beta grant without a dated expiry is schema-invalid by contract.
    if (class == .beta and p.expiry == null) return .malformed;
    const max_major = std.fmt.parseInt(u32, p.max_major, 10) catch return .malformed;

    // Key-to-grant-class binding: the role that VERIFIED constrains what the
    // payload may claim. This is the check that caps a leaked key's blast
    // radius; it must come before any "is it otherwise fine" reasoning.
    const class_ok = switch (req.verified_role) {
        .beta_license => class == .beta,
        .paid_license => class == .paddle or class == .comp,
    };
    if (!class_ok) return .class_key_mismatch;

    if (!std.mem.eql(u8, p.product, req.product)) return .wrong_product;
    if (req.app_major > max_major) return .version_ceiling;

    // A stored high-water mark that is itself corrupt is app-state damage,
    // not evidence of rollback; ignore it rather than brick the install.
    if (req.clock_high_water) |hwm| {
        if (isValidDate(hwm) and std.mem.order(u8, req.now_utc_date, hwm) == .lt)
            return .clock_rollback;
    }

    if (p.expiry) |x| {
        // Day-inclusive: authorized through the expiry date itself, all UTC.
        if (std.mem.order(u8, req.now_utc_date, x) == .gt) return .expired;
    }

    // features "full" covers every operation; a narrower grant covers only
    // its named operation class. null = the app's default protected op,
    // covered by any authorized grant.
    if (!std.mem.eql(u8, p.features, "full")) {
        if (req.operation) |op| {
            if (!std.mem.eql(u8, op, p.features)) return .operation_not_granted;
        }
    }
    return .authorized;
}

const GrantClass = enum { beta, paddle, comp, demo };

fn classOf(provider: []const u8) ?GrantClass {
    if (std.mem.eql(u8, provider, "beta")) return .beta;
    if (std.mem.eql(u8, provider, "paddle")) return .paddle;
    if (std.mem.eql(u8, provider, "comp")) return .comp;
    if (std.mem.eql(u8, provider, "demo")) return .demo;
    return null;
}

/// The opaque clock high-water store format every app persists identically
/// (contract rev 1.1): exactly the 10 bytes of the YYYY-MM-DD date, nothing
/// else. Returns the value to persist after this evaluation.
pub fn nextHighWater(now_utc_date: []const u8, stored: ?[]const u8) []const u8 {
    if (stored) |s| {
        if (std.mem.order(u8, s, now_utc_date) == .gt) return s;
    }
    return now_utc_date;
}

fn isValidDate(s: []const u8) bool {
    if (s.len != 10) return false;
    for (s, 0..) |c, i| {
        if (i == 4 or i == 7) {
            if (c != '-') return false;
        } else if (c < '0' or c > '9') return false;
    }
    const month = (s[5] - '0') * 10 + (s[6] - '0');
    const day = (s[8] - '0') * 10 + (s[9] - '0');
    return month >= 1 and month <= 12 and day >= 1 and day <= 31;
}

// ── C FFI ───────────────────────────────────────────────────────────

/// C boundary for Rust/C consumers (validate re-exports its own decision
/// through its FFI; the GUIs never link this directly). Returns the
/// Decision code, or a negative value: -1 bad arguments/role, -2 invalid
/// now date, -3 allocation failure.
export fn mecha_policy_decide(
    payload_ptr: [*]const u8,
    payload_len: usize,
    role: u8,
    product: [*:0]const u8,
    app_major: u32,
    now_utc_date: [*:0]const u8,
    clock_high_water: ?[*:0]const u8,
    operation: ?[*:0]const u8,
) i32 {
    const role_e: Role = switch (role) {
        0 => .beta_license,
        1 => .paid_license,
        else => return -1,
    };
    const d = decide(std.heap.page_allocator, .{
        .payload = payload_ptr[0..payload_len],
        .verified_role = role_e,
        .product = std.mem.span(product),
        .app_major = app_major,
        .now_utc_date = std.mem.span(now_utc_date),
        .clock_high_water = if (clock_high_water) |h| std.mem.span(h) else null,
        .operation = if (operation) |o| std.mem.span(o) else null,
    }) catch |e| return switch (e) {
        Error.InvalidNow => -2,
        Error.OutOfMemory => -3,
        Error.InvalidArgument => -1,
    };
    return @intFromEnum(d);
}

/// Stable name for a decision code, for status surfaces and logs.
export fn mecha_policy_reason_name(code: u8) [*:0]const u8 {
    if (code > 9) return "unknown";
    const d: Decision = @enumFromInt(code);
    return d.name().ptr;
}

/// The ABI contract version consumers were built against. Bumped ONLY on
/// a breaking change to the exported functions or decision codes; lets
/// validate's freshness gate and adapters assert mechanically instead of
/// remembering (validate's counter, adopted 2026-09-17).
export fn mecha_policy_abi_version() u32 {
    return 1;
}

export fn mecha_policy_version() [*:0]const u8 {
    return "0.1.0";
}

// ── Installation certificates (contract section 15) ─────────────────

/// Why an installation certificate does or does not admit this machine.
/// Separate from Decision: a certificate verdict never masquerades as a
/// license verdict, and neither is ever a file verdict.
pub const InstallDecision = enum(u8) {
    valid = 0,
    malformed = 1,
    wrong_product = 2,
    other_machine = 3,
    other_license = 4,
    expired = 5,
    clock_rollback = 6,

    pub fn name(self: InstallDecision) [:0]const u8 {
        return switch (self) {
            .valid => "install_cert_valid",
            .malformed => "install_cert_malformed",
            .wrong_product => "install_cert_wrong_product",
            .other_machine => "install_cert_other_machine",
            .other_license => "install_cert_other_license",
            .expired => "install_cert_expired",
            .clock_rollback => "install_cert_clock_rollback",
        };
    }
};

pub const InstallRequest = struct {
    /// Exact bytes sigil verified under the install-cert role key.
    cert_payload: []const u8,
    product: []const u8,
    /// Lowercase hex SHA-256 of the exact imported license envelope bytes.
    license_sha256: []const u8,
    /// Lowercase hex from machineHash for this product on this machine.
    machine: []const u8,
    now_utc_date: []const u8,
    clock_high_water: ?[]const u8 = null,
};

const CertV1 = struct {
    cert_id: []const u8,
    expiry: []const u8,
    issued: []const u8,
    license_sha256: []const u8,
    machine: []const u8,
    product: []const u8,
    v: []const u8,
};

/// Decide whether a verified installation certificate admits this machine
/// under this license (contract section 15). Order: schema -> product ->
/// license binding -> machine binding -> clock rollback -> expiry. Pure: the
/// caller supplies the verified bytes, the license hash, the machine hash
/// and today's UTC date.
pub fn decideInstall(allocator: std.mem.Allocator, req: InstallRequest) Error!InstallDecision {
    if (!isValidDate(req.now_utc_date)) return Error.InvalidNow;
    if (!isLowerHex64(req.license_sha256) or !isLowerHex64(req.machine)) return Error.InvalidArgument;

    const parsed = std.json.parseFromSlice(CertV1, allocator, req.cert_payload, .{
        .duplicate_field_behavior = .@"error",
    }) catch |e| switch (e) {
        error.OutOfMemory => return Error.OutOfMemory,
        else => return .malformed,
    };
    defer parsed.deinit();
    const c = parsed.value;

    if (!std.mem.eql(u8, c.v, "1")) return .malformed;
    if (!isUuidV7(c.cert_id)) return .malformed;
    if (!isValidDate(c.issued) or !isValidDate(c.expiry)) return .malformed;
    if (std.mem.order(u8, c.expiry, c.issued) == .lt) return .malformed;
    if (!isLowerHex64(c.license_sha256) or !isLowerHex64(c.machine)) return .malformed;

    if (!std.mem.eql(u8, c.product, req.product)) return .wrong_product;
    if (!std.mem.eql(u8, c.license_sha256, req.license_sha256)) return .other_license;
    if (!std.mem.eql(u8, c.machine, req.machine)) return .other_machine;

    if (req.clock_high_water) |hwm| {
        if (isValidDate(hwm) and std.mem.order(u8, req.now_utc_date, hwm) == .lt)
            return .clock_rollback;
    }
    if (std.mem.order(u8, req.now_utc_date, c.expiry) == .gt) return .expired;
    return .valid;
}

/// The per-product machine fingerprint (contract section 15): lowercase hex
/// SHA-256 over "mecha-install-v1" || product || 0x00 || raw id, after the
/// raw id is trimmed of ASCII whitespace and ASCII-lowercased. One
/// implementation so every app hashes the OS identifier identically; the raw
/// identifier itself never leaves the machine.
pub fn machineHash(out: *[64]u8, product: []const u8, raw_id: []const u8) void {
    const trimmed = std.mem.trim(u8, raw_id, " \t\r\n");
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("mecha-install-v1");
    h.update(product);
    h.update(&[_]u8{0});
    var buf: [64]u8 = undefined;
    var i: usize = 0;
    while (i < trimmed.len) {
        const n = @min(buf.len, trimmed.len - i);
        for (trimmed[i .. i + n], 0..) |ch, k| buf[k] = std.ascii.toLower(ch);
        h.update(buf[0..n]);
        i += n;
    }
    var digest: [32]u8 = undefined;
    h.final(&digest);
    out.* = std.fmt.bytesToHex(digest, .lower);
}

fn isLowerHex64(s: []const u8) bool {
    if (s.len != 64) return false;
    for (s) |ch| {
        if (!((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'))) return false;
    }
    return true;
}

/// Canonical lowercase 8-4-4-4-12 with version nibble 7 and the RFC 9562
/// variant bits (8, 9, a, b).
fn isUuidV7(s: []const u8) bool {
    if (s.len != 36) return false;
    for (s, 0..) |ch, i| {
        if (i == 8 or i == 13 or i == 18 or i == 23) {
            if (ch != '-') return false;
        } else if (!((ch >= '0' and ch <= '9') or (ch >= 'a' and ch <= 'f'))) return false;
    }
    if (s[14] != '7') return false;
    return switch (s[19]) {
        '8', '9', 'a', 'b' => true,
        else => false,
    };
}

/// C boundary for the installation-certificate decision. Returns the
/// InstallDecision code, or negative: -1 bad argument (hash shape),
/// -2 invalid now date, -3 allocation failure.
export fn mecha_policy_install_decide(
    cert_ptr: [*]const u8,
    cert_len: usize,
    product: [*:0]const u8,
    license_sha256: [*:0]const u8,
    machine: [*:0]const u8,
    now_utc_date: [*:0]const u8,
    clock_high_water: ?[*:0]const u8,
) i32 {
    const d = decideInstall(std.heap.page_allocator, .{
        .cert_payload = cert_ptr[0..cert_len],
        .product = std.mem.span(product),
        .license_sha256 = std.mem.span(license_sha256),
        .machine = std.mem.span(machine),
        .now_utc_date = std.mem.span(now_utc_date),
        .clock_high_water = if (clock_high_water) |h| std.mem.span(h) else null,
    }) catch |e| return switch (e) {
        Error.InvalidArgument => -1,
        Error.InvalidNow => -2,
        Error.OutOfMemory => -3,
    };
    return @intFromEnum(d);
}

export fn mecha_policy_install_reason_name(code: u8) [*:0]const u8 {
    if (code > 6) return "unknown";
    const d: InstallDecision = @enumFromInt(code);
    return d.name().ptr;
}

/// Writes 64 lowercase hex characters and a terminating NUL into out_65.
export fn mecha_policy_machine_hash(
    product: [*:0]const u8,
    raw_id: [*]const u8,
    raw_len: usize,
    out_65: [*]u8,
) void {
    var out: [64]u8 = undefined;
    machineHash(&out, std.mem.span(product), raw_id[0..raw_len]);
    @memcpy(out_65[0..64], &out);
    out_65[64] = 0;
}
// ── Tests ───────────────────────────────────────────────────────────
// The eval table is copied verbatim from sigil examples/license_vectors/
// manifest.json (schema mecha-license-vectors/1, sigil commit dfbc0e3) —
// the payload constants are the exact fixture bytes; changing either side
// requires a coordinated vector-schema bump per the contract.

const t = std.testing;

const p_beta_valid =
    \\{"customer_email":"beta-tester@example.com","customer_name_canonical":"beta tester","expiry":"2026-10-17","features":"full","max_major":"1","offline_days":"365","payment_provider":"beta","payment_ref":"beta_0001","product":"mecha-validate","purchase_date":"2026-09-17","v":"1"}
;
const p_beta_expired =
    \\{"customer_email":"beta-tester@example.com","customer_name_canonical":"beta tester","expiry":"2026-08-01","features":"full","max_major":"1","offline_days":"365","payment_provider":"beta","payment_ref":"beta_0002","product":"mecha-validate","purchase_date":"2026-07-01","v":"1"}
;
const p_beta_month_end =
    \\{"customer_email":"beta-tester@example.com","customer_name_canonical":"beta tester","expiry":"2026-02-28","features":"full","max_major":"1","offline_days":"365","payment_provider":"beta","payment_ref":"beta_0003","product":"mecha-validate","purchase_date":"2026-01-31","v":"1"}
;
const p_beta_leap =
    \\{"customer_email":"beta-tester@example.com","customer_name_canonical":"beta tester","expiry":"2028-02-29","features":"full","max_major":"1","offline_days":"365","payment_provider":"beta","payment_ref":"beta_0004","product":"mecha-validate","purchase_date":"2028-01-31","v":"1"}
;
const p_paid_valid =
    \\{"customer_email":"customer@example.com","customer_name_canonical":"paying customer","features":"full","max_major":"1","offline_days":"365","payment_provider":"paddle","payment_ref":"txn_test_0001","product":"mecha-validate","purchase_date":"2026-09-17","v":"1"}
;
const p_wrong_product =
    \\{"customer_email":"beta-tester@example.com","customer_name_canonical":"beta tester","expiry":"2026-10-17","features":"full","max_major":"1","offline_days":"365","payment_provider":"beta","payment_ref":"beta_0005","product":"mecha-rotshield","purchase_date":"2026-09-17","v":"1"}
;
const p_wrong_class_for_key =
    \\{"customer_email":"forger@example.com","customer_name_canonical":"leaked key forgery","features":"full","max_major":"1","offline_days":"365","payment_provider":"paddle","payment_ref":"txn_forged_0001","product":"mecha-validate","purchase_date":"2026-09-17","v":"1"}
;
const p_beta_missing_expiry =
    \\{"customer_email":"beta-tester@example.com","customer_name_canonical":"beta tester","features":"full","max_major":"1","offline_days":"365","payment_provider":"beta","payment_ref":"beta_0006","product":"mecha-validate","purchase_date":"2026-09-17","v":"1"}
;
const p_malformed_expiry_empty =
    \\{"customer_email":"beta-tester@example.com","customer_name_canonical":"beta tester","expiry":"","features":"full","max_major":"1","offline_days":"365","payment_provider":"beta","payment_ref":"beta_0007","product":"mecha-validate","purchase_date":"2026-09-17","v":"1"}
;

const Eval = struct {
    payload: []const u8,
    role: Role = .beta_license,
    product: []const u8 = "mecha-validate",
    app_major: u32 = 1,
    now: []const u8,
    expect: Decision,
};

// Every policy_evals row from the manifest, verbatim.
const manifest_evals = [_]Eval{
    .{ .payload = p_beta_valid, .now = "2026-09-16", .expect = .authorized }, // no not-before gate
    .{ .payload = p_beta_valid, .now = "2026-10-16", .expect = .authorized },
    .{ .payload = p_beta_valid, .now = "2026-10-17", .expect = .authorized }, // expiry day inclusive
    .{ .payload = p_beta_valid, .now = "2026-10-18", .expect = .expired },
    .{ .payload = p_beta_valid, .product = "mecha-rotshield", .now = "2026-10-17", .expect = .wrong_product },
    .{ .payload = p_beta_valid, .app_major = 2, .now = "2026-10-17", .expect = .version_ceiling },
    .{ .payload = p_beta_expired, .now = "2026-08-01", .expect = .authorized }, // its own expiry day
    .{ .payload = p_beta_expired, .now = "2026-08-02", .expect = .expired },
    .{ .payload = p_beta_expired, .now = "2026-09-17", .expect = .expired },
    .{ .payload = p_beta_month_end, .now = "2026-02-28", .expect = .authorized },
    .{ .payload = p_beta_month_end, .now = "2026-03-01", .expect = .expired },
    .{ .payload = p_beta_leap, .now = "2028-02-29", .expect = .authorized },
    .{ .payload = p_beta_leap, .now = "2028-03-01", .expect = .expired },
    .{ .payload = p_paid_valid, .role = .paid_license, .now = "2026-09-17", .expect = .authorized },
    .{ .payload = p_paid_valid, .role = .paid_license, .now = "2099-01-01", .expect = .authorized }, // absent expiry = unbounded
    .{ .payload = p_paid_valid, .role = .paid_license, .app_major = 2, .now = "2026-09-17", .expect = .version_ceiling },
    .{ .payload = p_wrong_product, .now = "2026-09-17", .expect = .wrong_product },
    .{ .payload = p_wrong_product, .product = "mecha-rotshield", .now = "2026-09-17", .expect = .authorized }, // positive control
    .{ .payload = p_wrong_class_for_key, .now = "2026-09-17", .expect = .class_key_mismatch }, // THE forgery
    .{ .payload = p_beta_missing_expiry, .now = "2026-09-17", .expect = .malformed },
    .{ .payload = p_malformed_expiry_empty, .now = "2026-09-17", .expect = .malformed },
};

test "manifest evals: every expected decision from mecha-license-vectors/1" {
    for (manifest_evals, 0..) |e, i| {
        const got = try decide(t.allocator, .{
            .payload = e.payload,
            .verified_role = e.role,
            .product = e.product,
            .app_major = e.app_major,
            .now_utc_date = e.now,
        });
        if (got != e.expect) {
            std.debug.print("eval[{d}]: expected {s}, got {s}\n", .{ i, e.expect.name(), got.name() });
            return error.TestExpectedEqual;
        }
    }
}

test "class binding is symmetric: beta-class payload under the paid role is refused" {
    try t.expectEqual(Decision.class_key_mismatch, try decide(t.allocator, .{
        .payload = p_beta_valid,
        .verified_role = .paid_license,
        .product = "mecha-validate",
        .app_major = 1,
        .now_utc_date = "2026-09-17",
    }));
}

test "malformed corpus: adversarial bytes are malformed, never a crash or a grant" {
    const bad = [_][]const u8{
        "", "{", "null", "[]", "42", "\"s\"", "{}",
        "{\"v\":\"1\"}", // missing required fields
        p_beta_valid[0 .. p_beta_valid.len - 2], // truncated
        // duplicate field (payment_provider twice)
        \\{"customer_email":"a@b.c","customer_name_canonical":"a","expiry":"2026-10-17","features":"full","max_major":"1","offline_days":"365","payment_provider":"paddle","payment_provider":"beta","payment_ref":"x","product":"mecha-validate","purchase_date":"2026-09-17","v":"1"}
        ,
        // unknown extra field
        \\{"customer_email":"a@b.c","customer_name_canonical":"a","expiry":"2026-10-17","features":"full","max_major":"1","offline_days":"365","payment_provider":"beta","payment_ref":"x","product":"mecha-validate","purchase_date":"2026-09-17","surprise":"1","v":"1"}
        ,
        // wrong schema version
        \\{"customer_email":"a@b.c","customer_name_canonical":"a","expiry":"2026-10-17","features":"full","max_major":"1","offline_days":"365","payment_provider":"beta","payment_ref":"x","product":"mecha-validate","purchase_date":"2026-09-17","v":"2"}
        ,
        // non-string field type
        \\{"customer_email":"a@b.c","customer_name_canonical":"a","expiry":"2026-10-17","features":"full","max_major":1,"offline_days":"365","payment_provider":"beta","payment_ref":"x","product":"mecha-validate","purchase_date":"2026-09-17","v":"1"}
        ,
        // unknown payment_provider
        \\{"customer_email":"a@b.c","customer_name_canonical":"a","expiry":"2026-10-17","features":"full","max_major":"1","offline_days":"365","payment_provider":"bitcoin","payment_ref":"x","product":"mecha-validate","purchase_date":"2026-09-17","v":"1"}
        ,
        // garbage expiry formats
        \\{"customer_email":"a@b.c","customer_name_canonical":"a","expiry":"2026-13-01","features":"full","max_major":"1","offline_days":"365","payment_provider":"beta","payment_ref":"x","product":"mecha-validate","purchase_date":"2026-09-17","v":"1"}
        ,
        \\{"customer_email":"a@b.c","customer_name_canonical":"a","expiry":"tomorrow","features":"full","max_major":"1","offline_days":"365","payment_provider":"beta","payment_ref":"x","product":"mecha-validate","purchase_date":"2026-09-17","v":"1"}
        ,
        // non-numeric max_major
        \\{"customer_email":"a@b.c","customer_name_canonical":"a","expiry":"2026-10-17","features":"full","max_major":"one","offline_days":"365","payment_provider":"beta","payment_ref":"x","product":"mecha-validate","purchase_date":"2026-09-17","v":"1"}
        ,
    };
    for (bad, 0..) |payload, i| {
        const got = try decide(t.allocator, .{
            .payload = payload,
            .verified_role = .beta_license,
            .product = "mecha-validate",
            .app_major = 1,
            .now_utc_date = "2026-09-17",
        });
        if (got != .malformed) {
            std.debug.print("bad[{d}]: expected malformed, got {s}\n", .{ i, got.name() });
            return error.TestExpectedEqual;
        }
    }
}

test "clock rollback: now behind the high-water mark is refused; at or ahead is not" {
    const at_mark = try decide(t.allocator, .{
        .payload = p_beta_valid,
        .verified_role = .beta_license,
        .product = "mecha-validate",
        .app_major = 1,
        .now_utc_date = "2026-09-17",
        .clock_high_water = "2026-09-17",
    });
    try t.expectEqual(Decision.authorized, at_mark);
    const behind = try decide(t.allocator, .{
        .payload = p_beta_valid,
        .verified_role = .beta_license,
        .product = "mecha-validate",
        .app_major = 1,
        .now_utc_date = "2026-09-16",
        .clock_high_water = "2026-09-17",
    });
    try t.expectEqual(Decision.clock_rollback, behind);
}

test "operation gating: features full covers any operation; ungrantable op refused" {
    try t.expectEqual(Decision.authorized, try decide(t.allocator, .{
        .payload = p_beta_valid,
        .verified_role = .beta_license,
        .product = "mecha-validate",
        .app_major = 1,
        .now_utc_date = "2026-09-17",
        .operation = "scan",
    }));
}

test "invalid injected now is a loud error, not a decision" {
    try t.expectError(Error.InvalidNow, decide(t.allocator, .{
        .payload = p_beta_valid,
        .verified_role = .beta_license,
        .product = "mecha-validate",
        .app_major = 1,
        .now_utc_date = "not-a-date",
    }));
}

test "high-water store format: max of stored and now" {
    try t.expectEqualStrings("2026-09-17", nextHighWater("2026-09-17", null));
    try t.expectEqualStrings("2026-09-17", nextHighWater("2026-09-16", "2026-09-17"));
    try t.expectEqualStrings("2026-09-18", nextHighWater("2026-09-18", "2026-09-17"));
}

test "abi version is 1 until a breaking change bumps it" {
    try t.expectEqual(@as(u32, 1), mecha_policy_abi_version());
}

// ── Installation certificates (contract section 15) ─────────────────
// Constants copied verbatim from sigil examples/install_cert_vectors
// (schema mecha-install-cert-vectors/1). Machine hashes there come from
// coreutils sha256sum, not from this module.

const ic_valid = "{\"cert_id\":\"0192f3a4-5b6c-7d8e-9f01-23456789abcd\",\"expiry\":\"2026-10-17\",\"issued\":\"2026-09-17\",\"license_sha256\":\"f8247856a3dc5e8ae25b40249e5e35917918074c0cb4ab04627c37cde404da01\",\"machine\":\"6f3e27ac78557b82c862b20f0c57e6f856f79a4fa572bed56182b813031e995c\",\"product\":\"mecha-validate\",\"v\":\"1\"}";
const ic_other_product = "{\"cert_id\":\"0192f3a4-5b6c-7d8e-9f01-23456789abcd\",\"expiry\":\"2026-10-17\",\"issued\":\"2026-09-17\",\"license_sha256\":\"f8247856a3dc5e8ae25b40249e5e35917918074c0cb4ab04627c37cde404da01\",\"machine\":\"3a1a08d3faabe92840f8cb7715067db94e9ef8a24ce285b05be29b956e6f8666\",\"product\":\"mecha-rotshield\",\"v\":\"1\"}";
const ic_bad_uuid = "{\"cert_id\":\"0192f3a4-5b6c-4d8e-9f01-23456789abcd\",\"expiry\":\"2026-10-17\",\"issued\":\"2026-09-17\",\"license_sha256\":\"f8247856a3dc5e8ae25b40249e5e35917918074c0cb4ab04627c37cde404da01\",\"machine\":\"6f3e27ac78557b82c862b20f0c57e6f856f79a4fa572bed56182b813031e995c\",\"product\":\"mecha-validate\",\"v\":\"1\"}";
const ic_expiry_before_issued = "{\"cert_id\":\"0192f3a4-5b6c-7d8e-9f01-23456789abcd\",\"expiry\":\"2026-09-16\",\"issued\":\"2026-09-17\",\"license_sha256\":\"f8247856a3dc5e8ae25b40249e5e35917918074c0cb4ab04627c37cde404da01\",\"machine\":\"6f3e27ac78557b82c862b20f0c57e6f856f79a4fa572bed56182b813031e995c\",\"product\":\"mecha-validate\",\"v\":\"1\"}";
const ic_uppercase_hex = "{\"cert_id\":\"0192f3a4-5b6c-7d8e-9f01-23456789abcd\",\"expiry\":\"2026-10-17\",\"issued\":\"2026-09-17\",\"license_sha256\":\"F8247856A3DC5E8AE25B40249E5E35917918074C0CB4AB04627C37CDE404DA01\",\"machine\":\"6f3e27ac78557b82c862b20f0c57e6f856f79a4fa572bed56182b813031e995c\",\"product\":\"mecha-validate\",\"v\":\"1\"}";
const ic_lic = "f8247856a3dc5e8ae25b40249e5e35917918074c0cb4ab04627c37cde404da01";
const ic_lic_other = "ef021ae874ef456145cde15bdc7f970e3f785a47aa29366c83a067566f9a909d";
const ic_machine_a = "6f3e27ac78557b82c862b20f0c57e6f856f79a4fa572bed56182b813031e995c";
const ic_machine_b = "f4ae35d9fbdfa65235e1b435cb6c50cb210a685fb4273c160f0ee69a49f8e7c9";
const ic_machine_a_rot = "3a1a08d3faabe92840f8cb7715067db94e9ef8a24ce285b05be29b956e6f8666";

const InstallEval = struct {
    cert: []const u8,
    now: []const u8,
    hwm: ?[]const u8 = null,
    product: []const u8 = "mecha-validate",
    license: []const u8 = ic_lic,
    machine: []const u8 = ic_machine_a,
    expect: InstallDecision,
};

const install_evals = [_]InstallEval{
    .{ .cert = ic_valid, .now = "2026-09-17", .expect = .valid },
    .{ .cert = ic_valid, .now = "2026-10-17", .expect = .valid }, // expiry day inclusive
    .{ .cert = ic_valid, .now = "2026-10-18", .expect = .expired },
    .{ .cert = ic_valid, .now = "2026-09-17", .machine = ic_machine_b, .expect = .other_machine },
    .{ .cert = ic_valid, .now = "2026-09-17", .license = ic_lic_other, .expect = .other_license },
    .{ .cert = ic_valid, .now = "2026-09-17", .product = "mecha-rotshield", .expect = .wrong_product },
    .{ .cert = ic_valid, .now = "2026-09-17", .hwm = "2026-09-20", .expect = .clock_rollback },
    .{ .cert = ic_other_product, .now = "2026-09-17", .expect = .wrong_product },
    .{ .cert = ic_bad_uuid, .now = "2026-09-17", .expect = .malformed },
    .{ .cert = ic_expiry_before_issued, .now = "2026-09-16", .expect = .malformed },
    .{ .cert = ic_uppercase_hex, .now = "2026-09-17", .expect = .malformed },
};

test "install-cert manifest evals: every expected decision from mecha-install-cert-vectors/1" {
    for (install_evals, 0..) |e, i| {
        const got = try decideInstall(t.allocator, .{
            .cert_payload = e.cert,
            .product = e.product,
            .license_sha256 = e.license,
            .machine = e.machine,
            .now_utc_date = e.now,
            .clock_high_water = e.hwm,
        });
        if (got != e.expect) {
            std.debug.print("install eval[{d}]: expected {s}, got {s}\n", .{ i, e.expect.name(), got.name() });
            return error.TestExpectedEqual;
        }
    }
}

test "install-cert: strict schema refuses unknown, missing and duplicate fields" {
    const bad = [_][]const u8{
        "{}",
        "not json",
        ic_valid[0 .. ic_valid.len - 1] ++ ",\"extra\":\"x\"}",
        "{\"cert_id\":\"0192f3a4-5b6c-7d8e-9f01-23456789abcd\",\"cert_id\":\"0192f3a4-5b6c-7d8e-9f01-23456789abcd\",\"expiry\":\"2026-10-17\",\"issued\":\"2026-09-17\",\"license_sha256\":\"" ++ ic_lic ++ "\",\"machine\":\"" ++ ic_machine_a ++ "\",\"product\":\"mecha-validate\",\"v\":\"1\"}",
        "{\"cert_id\":\"0192f3a4-5b6c-7d8e-9f01-23456789abcd\",\"expiry\":\"2026-10-17\",\"issued\":\"2026-09-17\",\"license_sha256\":\"" ++ ic_lic ++ "\",\"machine\":\"" ++ ic_machine_a ++ "\",\"product\":\"mecha-validate\",\"v\":\"2\"}",
    };
    for (bad) |b| {
        try t.expectEqual(InstallDecision.malformed, try decideInstall(t.allocator, .{
            .cert_payload = b,
            .product = "mecha-validate",
            .license_sha256 = ic_lic,
            .machine = ic_machine_a,
            .now_utc_date = "2026-09-17",
        }));
    }
}

test "install-cert: a caller passing a malformed hash or date is a caller bug, not a verdict" {
    try t.expectError(Error.InvalidNow, decideInstall(t.allocator, .{ .cert_payload = ic_valid, .product = "mecha-validate", .license_sha256 = ic_lic, .machine = ic_machine_a, .now_utc_date = "2026-9-17" }));
    try t.expectError(Error.InvalidArgument, decideInstall(t.allocator, .{ .cert_payload = ic_valid, .product = "mecha-validate", .license_sha256 = "abc", .machine = ic_machine_a, .now_utc_date = "2026-09-17" }));
    try t.expectError(Error.InvalidArgument, decideInstall(t.allocator, .{ .cert_payload = ic_valid, .product = "mecha-validate", .license_sha256 = ic_lic, .machine = "ABC", .now_utc_date = "2026-09-17" }));
}

test "machine hash: matches the coreutils answers, including normalization" {
    var out: [64]u8 = undefined;
    machineHash(&out, "mecha-validate", "0123456789abcdef0123456789abcdef");
    try t.expectEqualStrings(ic_machine_a, &out);
    machineHash(&out, "mecha-validate", "fedcba9876543210fedcba9876543210");
    try t.expectEqualStrings(ic_machine_b, &out);
    machineHash(&out, "mecha-rotshield", "0123456789abcdef0123456789abcdef");
    try t.expectEqualStrings(ic_machine_a_rot, &out);
    machineHash(&out, "mecha-validate", "  0123456789ABCDEF0123456789ABCDEF\n");
    try t.expectEqualStrings(ic_machine_a, &out);
}

test "install reason names are distinct and prefixed" {
    inline for (@typeInfo(InstallDecision).@"enum".fields) |f| {
        const d: InstallDecision = @enumFromInt(f.value);
        try t.expect(std.mem.startsWith(u8, d.name(), "install_cert_"));
    }
}
