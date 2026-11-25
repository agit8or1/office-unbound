//! Log and diagnostics sanitiser. Everything the agent or GUI logs, and every support bundle, passes through `redact`.
//! Removes bearer tokens, JWT-shaped strings, and the values of secret-bearing query/form parameters and JSON fields.

const SECRET_KEYS: &[&str] = &[
    "access_token", "refresh_token", "id_token", "code", "code_verifier", "client_secret", "password", "token", "state",
    "device_code", "user_code",
];

/// Redacts secrets in free text. Conservative: may over-redact, never under-redacts the known shapes.
pub fn redact(input: &str) -> String {
    let mut out = redact_bearer(input);
    out = redact_jwts(&out);
    for k in SECRET_KEYS {
        out = redact_kv(&out, k);
    }
    out
}

fn redact_bearer(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = find_ci(rest, "bearer ") {
        out.push_str(&rest[..i + 7]);
        let tail = &rest[i + 7..];
        let end = tail.find(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == ',').unwrap_or(tail.len());
        out.push_str("[REDACTED]");
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

fn find_ci(hay: &str, needle: &str) -> Option<usize> {
    hay.to_ascii_lowercase().find(needle)
}

fn is_b64url(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// JWTs: three base64url segments separated by dots, the first starting with "eyJ".
fn redact_jwts(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("eyJ") {
        let tail = &rest[i..];
        let end = tail.find(|c: char| !(is_b64url(c) || c == '.')).unwrap_or(tail.len());
        let cand = &tail[..end];
        out.push_str(&rest[..i]);
        if cand.split('.').count() >= 2 && cand.len() > 20 {
            out.push_str("[REDACTED-JWT]");
        } else {
            out.push_str(cand);
        }
        rest = &tail[end..];
    }
    out.push_str(rest);
    out
}

/// key=value (query/form) and "key":"value" (JSON) forms.
fn redact_kv(s: &str, key: &str) -> String {
    let mut out = s.to_string();
    for (pre, sep_end) in [(format!("{key}="), None), (format!("\"{key}\":\""), Some('"')), (format!("\"{key}\": \""), Some('"'))] {
        let mut res = String::with_capacity(out.len());
        let mut rest = out.as_str();
        while let Some(i) = rest.find(&pre) {
            // Only whole keys: the char before must not be part of an identifier (so "authcode=" is not "code=").
            let ok_boundary = i == 0 || !rest[..i].chars().last().map(|c| c.is_ascii_alphanumeric() || c == '_').unwrap_or(false);
            res.push_str(&rest[..i + pre.len()]);
            let tail = &rest[i + pre.len()..];
            if !ok_boundary {
                rest = tail;
                continue;
            }
            let end = match sep_end {
                Some(q) => tail.find(q).unwrap_or(tail.len()),
                None => tail.find(|c: char| c == '&' || c.is_whitespace() || c == '"' || c == '\'').unwrap_or(tail.len()),
            };
            if end > 0 {
                res.push_str("[REDACTED]");
            }
            rest = &tail[end..];
        }
        res.push_str(rest);
        out = res;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWT: &str = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJkb2N0ZXN0In0.c2lnbmF0dXJlLXNpZ25hdHVyZQ";

    #[test]
    fn bearer_and_jwt() {
        let r = redact(&format!("GET /dav Authorization: Bearer {JWT} ok"));
        assert!(!r.contains("eyJ"), "{r}");
        assert!(r.contains("Bearer [REDACTED]"));
        assert!(!redact(&format!("token {JWT}")).contains("c2lnbmF0"));
    }

    #[test]
    fn query_form_and_json() {
        let r = redact("http://127.0.0.1:5000/?code=abc123&state=xyz&session_state=s1");
        assert!(!r.contains("abc123") && !r.contains("xyz"), "{r}");
        let r = redact(r#"{"refresh_token":"opaque-r-tok","expires_in":300}"#);
        assert!(!r.contains("opaque-r-tok") && r.contains("expires_in"), "{r}");
        let r = redact("grant_type=refresh_token&refresh_token=AbC.dEf&client_id=x");
        assert!(!r.contains("AbC.dEf") && r.contains("client_id=x"), "{r}");
        let r = redact(r#"{"password": "hunter2"}"#);
        assert!(!r.contains("hunter2"), "{r}");
    }

    #[test]
    fn keeps_harmless_text() {
        assert_eq!(redact("sync finished: 12 files, 0 errors"), "sync finished: 12 files, 0 errors");
        assert_eq!(redact("errorcode=5"), "errorcode=5", "suffix match is not the key 'code'");
    }
}
