//! Anonymous account numbers (Mullvad-style).
//!
//! An account is identified solely by a random 16-digit number — no email, no
//! password, no PII. The number *is* the credential: clients send it as a bearer
//! token. This keeps the control plane's stored identity minimal (nothing to leak
//! beyond "this random number exists").

use rand_core::{OsRng, RngCore};

/// Number of decimal digits in an account number.
pub const ACCOUNT_DIGITS: usize = 16;

/// Generate a fresh random 16-digit account number.
pub fn generate_account_number() -> String {
    let mut bytes = [0u8; ACCOUNT_DIGITS];
    OsRng.fill_bytes(&mut bytes);
    // Map each byte to a digit. The modulo bias (256 % 10) is negligible for an
    // opaque identifier whose only requirement is unpredictability + uniqueness.
    bytes.iter().map(|b| char::from(b'0' + (b % 10))).collect()
}

/// True if `s` is a syntactically valid account number (exactly 16 ASCII digits).
/// Spaces/grouping are stripped by the caller before validation if desired.
pub fn is_valid_account_number(s: &str) -> bool {
    s.len() == ACCOUNT_DIGITS && s.bytes().all(|b| b.is_ascii_digit())
}

/// Format an account number for display in groups of four (e.g. `1234 5678 ...`).
pub fn format_grouped(number: &str) -> String {
    number
        .as_bytes()
        .chunks(4)
        .map(|c| std::str::from_utf8(c).unwrap_or(""))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_numbers_are_valid_and_unique() {
        let a = generate_account_number();
        let b = generate_account_number();
        assert!(is_valid_account_number(&a));
        assert!(is_valid_account_number(&b));
        assert_ne!(a, b);
    }

    #[test]
    fn rejects_malformed() {
        assert!(!is_valid_account_number("123"));
        assert!(!is_valid_account_number("12345678901234ab"));
        assert!(!is_valid_account_number(""));
    }

    #[test]
    fn grouping() {
        assert_eq!(format_grouped("1234567890123456"), "1234 5678 9012 3456");
    }
}
