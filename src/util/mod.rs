use base64;

pub fn encode_bin_to_base64(i: &[u8]) -> String {
    let config = base64::Config::new(
        base64::CharacterSet::UrlSafe,
        false,
        true,
        base64::LineWrap::NoWrap,
    );

    base64::encode_config(i, config)
}
