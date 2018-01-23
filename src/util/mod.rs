use base64;

pub fn bin_to_base64<T>(i: &T) -> String
where
    T: ?Sized + AsRef<[u8]>,
{
    let config = base64::Config::new(
        // Character set
        base64::CharacterSet::Standard,
        // Pad
        false,
        // Strip whitespace
        true,
        // Linewrapping
        base64::LineWrap::NoWrap,
    );

    base64::encode_config(i, config)
}

#[derive(Fail, Debug)]
#[fail(display = "base64 could not be decoded")]
pub struct Base64DecodeError {}

pub fn base64_to_bin<S>(i: &S) -> Result<Vec<u8>, Base64DecodeError>
where
    S: ?Sized + AsRef<[u8]>,
{
    let config = base64::Config::new(
        base64::CharacterSet::Standard,
        false,
        true,
        base64::LineWrap::NoWrap,
    );

    Ok(base64::decode_config(&i, config).map_err(|_| Base64DecodeError {})?)
}

#[cfg(test)]
mod tests {
    use util::*;

    // Test encoding against matrix spec
    // https://matrix.org/speculator/spec/drafts%2Fe2e/appendices.html#unpadded-base64

    #[test]
    fn encode_empty() {
        assert_eq!(bin_to_base64(&[]), "")
    }
    #[test]
    fn encode_f() {
        assert_eq!(bin_to_base64("f".as_bytes()), "Zg")
    }
    #[test]
    fn encode_fo() {
        assert_eq!(bin_to_base64("fo".as_bytes()), "Zm8")
    }
    #[test]
    fn encode_foo() {
        assert_eq!(bin_to_base64("foo".as_bytes()), "Zm9v")
    }
    #[test]
    fn encode_foobar() {
        assert_eq!(bin_to_base64("foobar".as_bytes()), "Zm9vYmFy")
    }

    #[test]
    fn decode_empty() {
        assert_eq!(base64_to_bin("").unwrap(), "".as_bytes())
    }
    #[test]
    fn decode_f() {
        assert_eq!(base64_to_bin("Zg").unwrap(), "f".as_bytes())
    }
    #[test]
    fn decode_foobar() {
        assert_eq!(base64_to_bin("Zm9vYmFy").unwrap(), "foobar".as_bytes())
    }

}
