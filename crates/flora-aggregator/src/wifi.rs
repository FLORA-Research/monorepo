//! The WiFi access-point dictionary.
//!
//! The dictionary lives in `wifi.toml` at the repository root and is baked
//! into the firmware with `include_str!` at build time. The firmware never
//! has an allocator, so the file is parsed into a fixed-size
//! [`heapless::Vec`] by a small TOML-subset reader below: exactly the file's
//! documented shape (a top-level `network` array of tables with `ssid`,
//! `password`, `auth`, `priority`) and nothing else. Anything outside that
//! shape is a parse error rather than silently ignored, because a typo in
//! a priority would otherwise reorder failover invisibly.
//!
//! Priority ordering and the [`Auth`]→`cyw43::JoinAuth` mapping are the
//! testable part; the join loop itself lives in the firmware binary.

use core::cmp::Ordering;
use heapless::Vec as HVec;

/// Most access points one deployment will ever list. The dictionary ships
/// with four; the cap keeps the static footprint bounded.
pub const MAX_NETWORKS: usize = 16;

/// Longest SSID the 802.11 standard allows.
pub const MAX_SSID_LEN: usize = 32;

/// Longest passphrase stored for one entry. WPA2 passphrases are at most
/// 63 characters; anything longer in the file is a parse error.
pub const MAX_PASSWORD_LEN: usize = 63;

/// Why a dictionary entry was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DictionaryError {
    /// A line outside the documented shape, or a bad key/value.
    Malformed(&'static str),
    /// The file lists more networks than the firmware can hold.
    TooManyNetworks,
    /// A required field is missing or out of range.
    InvalidField(&'static str),
    /// The same SSID appears twice: ambiguity about which credentials
    /// apply is worse than either choice.
    DuplicateSsid,
}

/// Authentication a network uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Auth {
    Open,
    Wpa,
    Wpa2,
    Wpa3,
    /// WPA2 and WPA3 mixed mode: what most current routers run.
    Wpa2Wpa3,
}

impl Auth {
    /// Parse the file's `auth = "..."` spelling.
    fn from_word(word: &str) -> Result<Self, DictionaryError> {
        match word {
            "open" => Ok(Auth::Open),
            "wpa" => Ok(Auth::Wpa),
            "wpa2" => Ok(Auth::Wpa2),
            "wpa3" => Ok(Auth::Wpa3),
            "wpa2wpa3" => Ok(Auth::Wpa2Wpa3),
            other => Err(DictionaryError::InvalidField(unknown_auth_word(other))),
        }
    }
}

fn unknown_auth_word(_: &str) -> &'static str {
    "unknown auth; expected open, wpa, wpa2, wpa3, or wpa2wpa3"
}

/// One access point from the dictionary, ready to be joined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WifiNetwork {
    pub ssid: HVec<u8, MAX_SSID_LEN>,
    /// Empty for an open network.
    pub password: HVec<u8, MAX_PASSWORD_LEN>,
    pub auth: Auth,
    /// Lower joins sooner. File order breaks ties.
    pub priority: u8,
    /// Parser bookkeeping: whether the file named `auth` for this entry.
    /// When it did not, the default is chosen from password presence.
    pub(crate) explicit_auth: bool,
}

impl WifiNetwork {
    /// SSID as `&str`, for `control.join`.
    pub fn ssid_str(&self) -> &str {
        core::str::from_utf8(&self.ssid).unwrap_or("")
    }

    /// Passphrase bytes for `JoinOptions`, empty for open networks.
    pub fn passphrase(&self) -> &[u8] {
        &self.password
    }

    /// Whether the entry is self-consistent: an open network must not
    /// carry a password, and a protected one must.
    pub fn is_consistent(&self) -> bool {
        match self.auth {
            Auth::Open => self.password.is_empty(),
            Auth::Wpa | Auth::Wpa2 | Auth::Wpa3 | Auth::Wpa2Wpa3 => !self.password.is_empty(),
        }
    }
}

/// Parse the whole dictionary. Returns the networks in join order.
///
/// The reader handles exactly the documented file shape:
///
/// ```text
/// [[network]]
/// ssid = "name"
/// password = "optional"
/// auth = "wpa2wpa3"
/// priority = 10
/// ```
///
/// Comments (`#`) to end of line, blank lines, and unknown *fields* are
/// the tolerated extras. Unknown fields are skipped so the file can carry
/// annotations the firmware does not read yet (e.g. a future `notes`),
/// but unknown *top-level* tables are refused, since a misspelled
/// `[[network]]` would otherwise silently produce an empty list and the
/// device would sit offline for no visible reason.
pub fn parse_dictionary(source: &str) -> Result<HVec<WifiNetwork, MAX_NETWORKS>, DictionaryError> {
    let mut networks: HVec<WifiNetwork, MAX_NETWORKS> = HVec::new();
    let mut in_network_table = false;
    let mut seen_ssids: [&str; MAX_NETWORKS] = [""; MAX_NETWORKS];
    let mut seen_count = 0usize;

    for (index, raw_line) in source.lines().enumerate() {
        let line = strip_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(table) = line.strip_prefix("[[") {
            let name = table
                .strip_suffix("]]")
                .ok_or(DictionaryError::Malformed("unterminated table header"))?
                .trim();
            if name == "network" {
                in_network_table = true;
                networks
                    .push(WifiNetwork {
                        ssid: HVec::new(),
                        password: HVec::new(),
                        auth: Auth::Open,
                        priority: 0,
                        explicit_auth: false,
                    })
                    .map_err(|_| DictionaryError::TooManyNetworks)?;
            } else {
                return Err(DictionaryError::Malformed("unknown table"));
            }
            continue;
        }
        if line.starts_with('[') {
            // A plain `[table]` or anything else in that family is not part
            // of the documented shape.
            return Err(DictionaryError::Malformed("unsupported table syntax"));
        }
        if !in_network_table {
            return Err(DictionaryError::Malformed("key before any [[network]]"));
        }

        let (key, value) = split_key_value(line, index)?;
        let current = networks
            .last_mut()
            .ok_or(DictionaryError::Malformed("no open table"))?;
        match key {
            "ssid" => {
                let text = parse_string(value)?;
                if text.is_empty() {
                    return Err(DictionaryError::InvalidField("ssid must not be empty"));
                }
                if text.len() > MAX_SSID_LEN {
                    return Err(DictionaryError::InvalidField("ssid too long"));
                }
                for seen in &seen_ssids[..seen_count] {
                    if *seen == text {
                        return Err(DictionaryError::DuplicateSsid);
                    }
                }
                if seen_count < MAX_NETWORKS {
                    seen_ssids[seen_count] = text;
                    seen_count += 1;
                }
                current
                    .ssid
                    .extend_from_slice(text.as_bytes())
                    .map_err(|_| DictionaryError::InvalidField("ssid too long"))?;
            }
            "password" => {
                let text = parse_string(value)?;
                if text.len() > MAX_PASSWORD_LEN {
                    return Err(DictionaryError::InvalidField("password too long"));
                }
                current
                    .password
                    .extend_from_slice(text.as_bytes())
                    .map_err(|_| DictionaryError::InvalidField("password too long"))?;
            }
            "auth" => {
                current.auth = Auth::from_word(parse_string(value)?)?;
                current.explicit_auth = true;
            }
            "priority" => {
                current.priority = parse_u8(value)?;
            }
            // Unknown fields inside a table are tolerated annotations.
            _ => {}
        }
    }

    for network in &mut networks {
        if network.ssid.is_empty() {
            return Err(DictionaryError::InvalidField("network without an ssid"));
        }
        // The file's contract: an entry with no `auth` line is `wpa2wpa3`
        // when a password is present and `open` when one is not. Resolve
        // the default here, after parsing, so a password-only entry is
        // protected rather than mis-read as open with credentials.
        if network.explicit_auth {
            if !network.is_consistent() {
                return Err(DictionaryError::InvalidField(
                    "password and auth disagree; open networks need no password",
                ));
            }
        } else {
            network.auth = if network.password.is_empty() {
                Auth::Open
            } else {
                Auth::Wpa2Wpa3
            };
        }
    }

    let mut ordered = networks;
    sort_by_priority(&mut ordered);
    Ok(ordered)
}

/// Join order: priority ascending, file order breaking ties.
///
/// Written by hand because the firmware has no allocator for the sorting
/// buffer a generic `sort_by_key` might want; an insertion sort over a
/// fixed-size vector is boring and stable.
fn sort_by_priority(networks: &mut HVec<WifiNetwork, MAX_NETWORKS>) {
    for i in 1..networks.len() {
        let mut j = i;
        while j > 0 {
            let a = &networks[j - 1];
            let b = &networks[j];
            if a.priority <= b.priority {
                break;
            }
            networks.swap(j - 1, j);
            j -= 1;
        }
    }
}

/// Join attempt order relative check used by tests and diagnostics.
pub fn join_order_cmp(a: &WifiNetwork, b: &WifiNetwork) -> Ordering {
    a.priority.cmp(&b.priority)
}

fn strip_comment(line: &str) -> &str {
    // A `#` only starts a comment outside a quoted value; the file's values
    // are short and ASCII, so a single scan that respects quotes is enough.
    let mut in_quotes = false;
    let mut escaped = false;
    for (index, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_quotes => escaped = true,
            '"' => in_quotes = !in_quotes,
            '#' if !in_quotes => return &line[..index],
            _ => {}
        }
    }
    line
}

fn split_key_value(line: &str, _line_number: usize) -> Result<(&str, &str), DictionaryError> {
    let (key, value) = line
        .split_once('=')
        .ok_or(DictionaryError::Malformed("expected key = value"))?;
    Ok((key.trim(), value.trim()))
}

/// Parse a quoted TOML basic string.
fn parse_string(value: &str) -> Result<&str, DictionaryError> {
    let value = value.trim();
    let Some(rest) = value.strip_prefix('"') else {
        return Err(DictionaryError::Malformed("expected a quoted string"));
    };
    let Some(end) = rest.strip_suffix('"') else {
        return Err(DictionaryError::Malformed("unterminated string"));
    };
    if end.contains('"') {
        return Err(DictionaryError::Malformed("embedded quote"));
    }
    Ok(end)
}

fn parse_u8(value: &str) -> Result<u8, DictionaryError> {
    value
        .parse::<u8>()
        .map_err(|_| DictionaryError::InvalidField("priority must be 0..=255"))
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::format;
    use alloc::string::String;

    fn dict(source: &str) -> HVec<WifiNetwork, MAX_NETWORKS> {
        parse_dictionary(source).unwrap()
    }

    fn ssid_of(networks: &HVec<WifiNetwork, MAX_NETWORKS>, index: usize) -> &str {
        networks[index].ssid_str()
    }

    #[test]
    fn parses_the_documented_shape() {
        let networks = dict(
            r#"
            [[network]]
            ssid = "home"
            password = "secret"
            auth = "wpa2"
            priority = 5

            [[network]]
            ssid = "setup"
            "#,
        );
        assert_eq!(networks.len(), 2);
        assert_eq!(ssid_of(&networks, 0), "setup");
        assert_eq!(ssid_of(&networks, 1), "home");
        assert_eq!(networks[1].auth, Auth::Wpa2);
        assert_eq!(networks[0].auth, Auth::Open);
    }

    #[test]
    fn priority_orders_the_join_attempt() {
        let networks = dict(
            r#"
            [[network]]
            ssid = "third"
            password = "x"
            priority = 20

            [[network]]
            ssid = "first"
            password = "x"
            priority = 1

            [[network]]
            ssid = "second"
            password = "x"
            priority = 10
            "#,
        );
        assert_eq!(ssid_of(&networks, 0), "first");
        assert_eq!(ssid_of(&networks, 1), "second");
        assert_eq!(ssid_of(&networks, 2), "third");
    }

    #[test]
    fn file_order_breaks_priority_ties() {
        let networks = dict(
            r#"
            [[network]]
            ssid = "alpha"
            password = "x"

            [[network]]
            ssid = "beta"
            password = "x"
            "#,
        );
        assert_eq!(ssid_of(&networks, 0), "alpha");
        assert_eq!(ssid_of(&networks, 1), "beta");
    }

    #[test]
    fn every_auth_spelling_is_accepted() {
        let networks = dict(
            r#"
            [[network]]
            ssid = "a"
            auth = "open"

            [[network]]
            ssid = "b"
            password = "p"
            auth = "wpa"

            [[network]]
            ssid = "c"
            password = "p"
            auth = "wpa2"

            [[network]]
            ssid = "d"
            password = "p"
            auth = "wpa3"

            [[network]]
            ssid = "e"
            password = "p"
            auth = "wpa2wpa3"
            "#,
        );
        assert_eq!(networks[0].auth, Auth::Open);
        assert_eq!(networks[1].auth, Auth::Wpa);
        assert_eq!(networks[2].auth, Auth::Wpa2);
        assert_eq!(networks[3].auth, Auth::Wpa3);
        assert_eq!(networks[4].auth, Auth::Wpa2Wpa3);
    }

    #[test]
    fn unknown_auth_is_an_error() {
        assert!(
            parse_dictionary("[[network]]\nssid = \"a\"\npassword = \"p\"\nauth = \"wpa99\"\n")
                .is_err()
        );
    }

    #[test]
    fn comments_and_blanks_are_skipped() {
        let networks = dict(
            "# header comment\n\n[[network]] # trailing\nssid = \"a\" # eol\npassword = \"p\"\n",
        );
        assert_eq!(networks.len(), 1);
        assert_eq!(ssid_of(&networks, 0), "a");
    }

    #[test]
    fn hash_inside_a_value_is_not_a_comment() {
        let networks = dict("[[network]]\nssid = \"a#b\"\npassword = \"p#1\"\n");
        assert_eq!(ssid_of(&networks, 0), "a#b");
        assert_eq!(networks[0].password.as_slice(), b"p#1");
    }

    #[test]
    fn duplicate_ssids_are_refused() {
        let error = parse_dictionary(
            "[[network]]\nssid = \"same\"\npassword = \"p\"\n\n[[network]]\nssid = \"same\"\npassword = \"q\"\n",
        )
        .unwrap_err();
        assert_eq!(error, DictionaryError::DuplicateSsid);
    }

    #[test]
    fn open_network_must_not_have_a_password() {
        let error =
            parse_dictionary("[[network]]\nssid = \"a\"\npassword = \"p\"\nauth = \"open\"\n")
                .unwrap_err();
        assert!(matches!(error, DictionaryError::InvalidField(_)));
    }

    #[test]
    fn encrypted_network_must_have_a_password() {
        let error = parse_dictionary("[[network]]\nssid = \"a\"\nauth = \"wpa2\"\n").unwrap_err();
        assert!(matches!(error, DictionaryError::InvalidField(_)));
    }

    #[test]
    fn ssid_is_bounded() {
        let long = "s".repeat(MAX_SSID_LEN + 1);
        let source = format!("[[network]]\nssid = \"{long}\"\n");
        assert!(parse_dictionary(&source).is_err());
    }

    #[test]
    fn more_networks_than_the_cap_is_an_error() {
        let mut source = String::new();
        for index in 0..(MAX_NETWORKS + 1) {
            source.push_str(&format!(
                "[[network]]\nssid = \"net{index}\"\npassword = \"p\"\n"
            ));
        }
        assert_eq!(
            parse_dictionary(&source).unwrap_err(),
            DictionaryError::TooManyNetworks
        );
    }

    #[test]
    fn misspelled_table_is_refused_so_an_empty_list_cannot_look_normal() {
        assert_eq!(
            parse_dictionary("[[netwrk]]\nssid = \"a\"\n").unwrap_err(),
            DictionaryError::Malformed("unknown table")
        );
        assert!(parse_dictionary("ssid = \"a\"\n").is_err());
    }

    #[test]
    fn unknown_fields_inside_a_table_are_tolerated() {
        let networks = dict("[[network]]\nssid = \"a\"\npassword = \"p\"\nnotes = \"x\"\n");
        assert_eq!(networks.len(), 1);
    }

    #[test]
    fn the_shipped_dictionary_parses() {
        // Parse the real file the firmware bakes in, so editing wifi.toml
        // can never silently break the build's network setup.
        let networks = parse_dictionary(include_str!("../../../wifi.toml")).unwrap();
        assert!(!networks.is_empty());
        for network in &networks {
            assert!(network.is_consistent());
            assert!(!network.ssid.is_empty());
        }
    }

    #[test]
    fn join_order_cmp_agrees_with_parse_order() {
        let networks = dict(
            "[[network]]\nssid = \"a\"\npassword = \"p\"\npriority = 2\n\n[[network]]\nssid = \"b\"\npassword = \"p\"\npriority = 1\n",
        );
        assert_eq!(join_order_cmp(&networks[0], &networks[1]), Ordering::Less);
    }
}
