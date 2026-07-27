//! Saved TUI profiles so the clients don't need every flag on each launch.
//!
//! Both TUIs read a small TOML file (default `~/.config/oxide/<name>.toml`); command-line
//! flags override whatever the file provides, and a value absent from both is a clear error at
//! startup. Each binary defines its own profile struct (all fields optional) and merges it with
//! its parsed flags — this module just locates and parses the file.

use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;

/// Something went wrong reading or parsing a profile file.
#[derive(Debug, thiserror::Error)]
pub enum ProfileError {
    #[error("reading {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("parsing {path}: {source}")]
    Parse {
        path: String,
        source: toml::de::Error,
    },
}

/// Base config directory: `$XDG_CONFIG_HOME/oxide`, else `$HOME/.config/oxide`.
pub fn config_dir() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .map(|base| base.join("oxide"))
}

/// Default path for a named profile, e.g. `client` → `~/.config/oxide/client.toml`.
pub fn default_path(name: &str) -> Option<PathBuf> {
    config_dir().map(|d| d.join(format!("{name}.toml")))
}

/// Load and parse a TOML profile. Returns `Ok(None)` if the file simply doesn't exist (running
/// with flags only is fine); a malformed file is a hard error so typos don't pass silently.
pub fn load<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, ProfileError> {
    match std::fs::read_to_string(path) {
        Ok(s) => toml::from_str(&s)
            .map(Some)
            .map_err(|source| ProfileError::Parse {
                path: path.display().to_string(),
                source,
            }),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(source) => Err(ProfileError::Io {
            path: path.display().to_string(),
            source,
        }),
    }
}

/// Load the profile named `name` (default location), or the one at `explicit` if given. A
/// missing default file yields `None`; a missing *explicit* file is an error (the user asked
/// for it), as is any parse failure. This is the entry point the TUIs call.
pub fn load_named<T: DeserializeOwned>(
    name: &str,
    explicit: Option<&Path>,
) -> Result<Option<T>, ProfileError> {
    match explicit {
        Some(p) => match load(p)? {
            Some(v) => Ok(Some(v)),
            None => Err(ProfileError::Io {
                path: p.display().to_string(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, "profile file not found"),
            }),
        },
        None => match default_path(name) {
            Some(p) => load(&p),
            None => Ok(None),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Debug, Deserialize, Default, PartialEq)]
    struct Sample {
        #[serde(default)]
        control_plane: Option<String>,
        #[serde(default)]
        account: Option<String>,
    }

    fn tmp(name: &str, body: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!("oxide-prof-{}-{name}", std::process::id()));
        std::fs::write(&p, body).unwrap();
        p
    }

    #[test]
    fn missing_default_is_none_not_error() {
        let p = std::env::temp_dir().join("oxide-prof-does-not-exist-xyz.toml");
        let _ = std::fs::remove_file(&p);
        let got: Option<Sample> = load(&p).unwrap();
        assert!(got.is_none());
    }

    #[test]
    fn parses_present_fields() {
        let p = tmp("ok.toml", "control_plane = \"http://cp:8080\"\n");
        let got: Sample = load(&p).unwrap().unwrap();
        assert_eq!(got.control_plane.as_deref(), Some("http://cp:8080"));
        assert_eq!(got.account, None);
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn malformed_is_an_error() {
        let p = tmp("bad.toml", "control_plane = \n");
        let got: Result<Option<Sample>, _> = load(&p);
        assert!(matches!(got, Err(ProfileError::Parse { .. })));
        std::fs::remove_file(&p).ok();
    }

    #[test]
    fn explicit_missing_is_an_error() {
        let p = std::env::temp_dir().join("oxide-prof-explicit-missing.toml");
        let _ = std::fs::remove_file(&p);
        let got: Result<Option<Sample>, _> = load_named("client", Some(&p));
        assert!(matches!(got, Err(ProfileError::Io { .. })));
    }
}
