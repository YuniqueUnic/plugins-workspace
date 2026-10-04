use std::io::{self, Cursor, Read, Write};

use base64::{Engine, engine::general_purpose::STANDARD};

use crate::updater::verify_to_file;

// Public test vector from minisign-verify 0.2.5; it signs the four bytes "test".
const PUBLIC_KEY: &str =
    "untrusted comment: public test key\nRWQf6LRCGA9i53mlYecO4IzT51TGPpvWucNSCh1CBM0QTaLn73Y7GFO3";
const SIGNATURE: &str = "untrusted comment: signature from minisign secret key\nRUQf6LRCGA9i559r3g7V1qNyJDApGip8MfqcadIgT9CuhV3EMhHoN1mGTkUidF/z7SrlQgXdy8ofjb7bNJJylDOocrCo8KLzZwo=\ntrusted comment: timestamp:1556193335\tfile:test\ny/rUw2y8/hOUYjZU71eHp/Wo1KZ40fGy2VJEDl34XMJM+TX48Ss/17u3IvIfbVR1FkZZSNCisQbuQY+bHwhEBg==";

struct OneByteReader(Cursor<Vec<u8>>);
impl Read for OneByteReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        let count = output.len().min(1);
        self.0.read(&mut output[..count])
    }
}

#[test]
fn verifies_fragmented_input_and_returns_a_rewound_private_snapshot() {
    let reader = OneByteReader(Cursor::new(b"test".to_vec()));
    let mut package = verify_to_file(
        reader,
        &STANDARD.encode(SIGNATURE),
        &STANDARD.encode(PUBLIC_KEY),
        "1.2.3",
        false,
    )
    .unwrap();
    let mut content = Vec::new();
    package.read_to_end(&mut content).unwrap();
    assert_eq!(content, b"test");
}

#[test]
fn rejects_modified_truncated_and_extended_packages() {
    for content in [b"tesX".as_slice(), b"tes", b"test!"] {
        assert!(
            verify_to_file(
                content,
                &STANDARD.encode(SIGNATURE),
                &STANDARD.encode(PUBLIC_KEY),
                "1.2.3",
                false,
            )
            .is_err()
        );
    }
}

#[test]
fn rejects_a_changed_signature() {
    let corrupt = SIGNATURE.replace("y/rUw2y8", "z/rUw2y8");
    assert!(
        verify_to_file(
            b"test".as_slice(),
            &STANDARD.encode(corrupt),
            &STANDARD.encode(PUBLIC_KEY),
            "1.2.3",
            false,
        )
        .is_err()
    );
}

#[test]
fn retains_input_io_failure() {
    struct Broken;
    impl Read for Broken {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "injected input failure",
            ))
        }
    }
    let result = verify_to_file(
        Broken,
        &STANDARD.encode(SIGNATURE),
        &STANDARD.encode(PUBLIC_KEY),
        "1.2.3",
        false,
    );
    assert!(matches!(result, Err(crate::Error::Io(_))));
}

#[test]
fn source_replacement_cannot_change_the_authenticated_snapshot() {
    let mut source = tempfile::NamedTempFile::new().unwrap();
    source.write_all(b"test").unwrap();
    source.flush().unwrap();
    let mut authenticated = verify_to_file(
        source.reopen().unwrap(),
        &STANDARD.encode(SIGNATURE),
        &STANDARD.encode(PUBLIC_KEY),
        "1.2.3",
        false,
    )
    .unwrap();
    std::fs::write(source.path(), b"replaced after verification").unwrap();
    let mut bytes = Vec::new();
    authenticated.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"test");
}

#[test]
fn signature_from_another_public_key_is_rejected() {
    let (comment, encoded) = PUBLIC_KEY.split_once('\n').unwrap();
    let mut key = STANDARD.decode(encoded).unwrap();
    *key.last_mut().unwrap() ^= 1;
    let other_key = format!("{comment}\n{}", STANDARD.encode(key));
    assert!(
        verify_to_file(
            b"test".as_slice(),
            &STANDARD.encode(SIGNATURE),
            &STANDARD.encode(other_key),
            "1.2.3",
            false,
        )
        .is_err()
    );
}

// Deterministic test fixture: Ed25519 seed [7; 32], key ID "SYZYGY01",
// BLAKE2b-512("test"); global signature covers the data signature + trusted comment.
const VERSION_PUBLIC_KEY: &str = "untrusted comment: deterministic public test key\nRWRTWVpZR1kwMepKbGPinFIKvvVQexMuxfmVR3auvr57kkIe6mkURtIs";
const VERSION_SIGNATURE: &str = "untrusted comment: deterministic version test\nRURTWVpZR1kwMRh0od4foi9vkvb4iisNrDD8+mHIhwhSI7T4vRrHtGY5mLCnK5qqaRTd29Unl3vY9jMAiPhE5/iowuCEI5mb8A0=\ntrusted comment: timestamp:1700000000\tfile:test\tversion:1.2.3\nFtb43zKy8rmODG/epJSOlDXPVBz51rGuM1lZ0hbRu6oODTkse8cTrQAORo+7eZBippO7HNTCV4bOqr+kwGLkCg==";

#[test]
fn streaming_verification_enforces_the_signed_version() {
    for require in [false, true] {
        for announced in ["1.2.3", "v1.2.3"] {
            let mut package = verify_to_file(
                b"test".as_slice(),
                &STANDARD.encode(VERSION_SIGNATURE),
                &STANDARD.encode(VERSION_PUBLIC_KEY),
                announced,
                require,
            )
            .unwrap();
            let mut bytes = Vec::new();
            package.read_to_end(&mut bytes).unwrap();
            assert_eq!(bytes, b"test");
        }
        assert!(matches!(
            verify_to_file(
                b"test".as_slice(),
                &STANDARD.encode(VERSION_SIGNATURE),
                &STANDARD.encode(VERSION_PUBLIC_KEY),
                "9.9.9",
                require,
            ),
            Err(crate::Error::SignedVersionMismatch { signed, announced })
                if signed == "1.2.3" && announced == "9.9.9"
        ));
    }
}

#[test]
fn streaming_verification_requires_a_version_when_configured() {
    assert!(matches!(
        verify_to_file(
            b"test".as_slice(),
            &STANDARD.encode(SIGNATURE),
            &STANDARD.encode(PUBLIC_KEY),
            "1.2.3",
            true,
        ),
        Err(crate::Error::MissingSignedVersion)
    ));
}

#[test]
fn authenticates_the_trusted_comment_before_using_its_version() {
    let forged = VERSION_SIGNATURE.replace("version:1.2.3", "version:9.9.9");
    assert!(matches!(
        verify_to_file(
            b"test".as_slice(),
            &STANDARD.encode(forged),
            &STANDARD.encode(VERSION_PUBLIC_KEY),
            "9.9.9",
            true,
        ),
        Err(crate::Error::Minisign(_))
    ));
}
