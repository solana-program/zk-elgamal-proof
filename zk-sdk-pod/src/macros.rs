macro_rules! impl_from_str {
    (TYPE = $type:ident, BYTES_LEN = $bytes_len:expr, BASE64_LEN = $base64_len:expr) => {
        impl core::str::FromStr for $type {
            type Err = crate::errors::ParseError;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                if s.len() > $base64_len {
                    return Err(Self::Err::WrongSize);
                }
                let mut bytes = [0u8; $bytes_len];
                let decoded_len = BASE64_STANDARD
                    .decode_slice(s, &mut bytes)
                    .map_err(|_| Self::Err::Invalid)?;
                if decoded_len != $bytes_len {
                    Err(Self::Err::WrongSize)
                } else {
                    Ok($type(bytes))
                }
            }
        }
    };
}
pub(crate) use impl_from_str;

macro_rules! impl_from_bytes {
    (TYPE = $type:ident, BYTES_LEN = $bytes_len:expr) => {
        impl core::convert::From<[u8; $bytes_len]> for $type {
            fn from(bytes: [u8; $bytes_len]) -> Self {
                Self(bytes)
            }
        }
    };
}
pub(crate) use impl_from_bytes;

#[cfg(feature = "serde-traits")]
macro_rules! impl_serde_base64 {
    (TYPE = $type:ident) => {
        impl serde::Serialize for $type {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                // collect_str safely routes through the existing Display trait
                serializer.collect_str(self)
            }
        }

        impl<'de> serde::Deserialize<'de> for $type {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: serde::Deserializer<'de>,
            {
                struct Base64Visitor;
                impl<'de> serde::de::Visitor<'de> for Base64Visitor {
                    type Value = $type;

                    fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                        formatter.write_str("a base64 encoded string")
                    }

                    fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                    where
                        E: serde::de::Error,
                    {
                        // Routes through the existing FromStr trait
                        core::str::FromStr::from_str(v).map_err(serde::de::Error::custom)
                    }
                }
                deserializer.deserialize_str(Base64Visitor)
            }
        }
    };
}
#[cfg(feature = "serde-traits")]
pub(crate) use impl_serde_base64;
