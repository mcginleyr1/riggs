//! `setup`: the per-user state directory, its throwaway certificate authority and the add-in
//! manifest. It never touches a keychain; it prints the commands only the user may run.

use std::fs::{self, OpenOptions, Permissions};
use std::io::{ErrorKind, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;

use anyhow::{bail, Context};
use rcgen::{
    BasicConstraints, CertificateParams, CidrSubnet, DistinguishedName, DnType,
    ExtendedKeyUsagePurpose, GeneralSubtree, IsCa, Issuer, KeyPair, KeyUsagePurpose,
    NameConstraints,
};
use rustls::pki_types::{pem::PemObject, CertificateDer};
use time::{Duration, OffsetDateTime};

const DEFAULT_PORT: u16 = 41443;
/// Apple refuses TLS server certificates valid for more than 825 days
/// (https://support.apple.com/en-us/103769); this stays clear of the boundary.
const VALIDITY_DAYS: i64 = 800;
const RENEW_WITHIN_DAYS: i64 = 30;

pub fn setup(dir: &Path, assets: &Path, port: Option<u16>, renew: bool) -> anyhow::Result<String> {
    fs::create_dir_all(dir).with_context(|| format!("cannot create {}", dir.display()))?;
    fs::set_permissions(dir, Permissions::from_mode(0o700))?;
    let dir = dir.canonicalize()?;
    let template_path = assets.join("manifest.template.xml");
    let template = fs::read_to_string(&template_path)
        .with_context(|| format!("cannot read {}", template_path.display()))?;

    let token = match read_if_present(&dir.join("token"))? {
        Some(token) if !renew => token,
        _ => {
            let mut bytes = [0u8; 16];
            getrandom::fill(&mut bytes)?;
            bytes.iter().map(|byte| format!("{byte:02x}")).collect()
        }
    };
    if !is_token(&token) {
        bail!(
            "{} is malformed; run setup with --renew",
            dir.join("token").display()
        );
    }
    let port = match port {
        Some(port) => port,
        None => read_if_present(&dir.join("port"))?
            .map_or(Ok(DEFAULT_PORT), |port| port.parse())
            .context("the state's port file is malformed; pass --port")?,
    };
    let manifest = template
        .replace("{{PORT}}", &port.to_string())
        .replace("{{TOKEN}}", &token);
    if !template.contains("{{TOKEN}}") || manifest.contains("{{") {
        bail!(
            "{} must use {} and no placeholder but {} and {}",
            template_path.display(),
            "{{TOKEN}}",
            "{{PORT}}",
            "{{TOKEN}}"
        );
    }

    let cert = dir.join("cert.pem");
    let keep = !renew
        && dir.join("key.pem").exists()
        && dir.join("ca.pem").exists()
        && cert.exists()
        && time_left(&cert)?.is_some_and(|left| left > Duration::days(RENEW_WITHIN_DAYS));
    if !keep {
        let (ca, leaf, key) = certificates()?;
        write_private(&dir.join("key.pem"), &key)?;
        write_private(&cert, &(leaf + &ca))?;
        write_private(&dir.join("ca.pem"), &ca)?;
    }
    let days_left = time_left(&cert)?
        .context("the certificate is not valid now")?
        .whole_days();
    write_private(&dir.join("token"), &token)?;
    write_private(&dir.join("port"), &port.to_string())?;
    write_private(&dir.join("manifest.xml"), &manifest)?;

    let quoted_ca = format!(
        "'{}'",
        dir.join("ca.pem")
            .display()
            .to_string()
            .replace('\'', r"'\''")
    );
    Ok(format!(
        "riggs-mailbridge state: {dir}
Certificate: {status}, valid for {days_left} more days.

Two steps only you can take; riggs-mailbridge does not run them.

1. Trust the bridge's local certificate authority for TLS in your login keychain
   (macOS asks for your password). Run it again after every new certificate:

   security add-trusted-cert -r trustRoot -p ssl -k \"$HOME/Library/Keychains/login.keychain-db\" {quoted_ca}

2. Add the add-in to your mailbox, again after --renew or a new port: in a browser
   signed in to the mailbox, open https://aka.ms/olksideload, choose My add-ins,
   then under Custom Addins choose Add a custom add-in, Add from File, and pick:

   {manifest}
",
        dir = dir.display(),
        status = if keep { "unchanged" } else { "new" },
        manifest = dir.join("manifest.xml").display(),
    ))
}

pub fn is_token(token: &str) -> bool {
    token.len() == 32
        && token
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

/// Time until the first certificate in `cert` expires; `None` when it is not valid now.
pub fn time_left(cert: &Path) -> anyhow::Result<Option<Duration>> {
    let der = CertificateDer::from_pem_file(cert)
        .with_context(|| format!("cannot read a certificate from {}", cert.display()))?;
    let (_, parsed) = x509_parser::parse_x509_certificate(&der)
        .with_context(|| format!("{} holds no valid certificate", cert.display()))?;
    Ok(parsed.validity().time_to_expiration())
}

/// A CA whose key is dropped on return, and a leaf for `localhost` and `127.0.0.1` it signed:
/// `(CA PEM, leaf PEM, leaf key PEM)`. ECDSA P-256 with SHA-256, because rcgen's ring backend
/// cannot generate RSA keys; Apple's key-size rule covers RSA only.
fn certificates() -> anyhow::Result<(String, String, String)> {
    let now = OffsetDateTime::now_utc();
    let not_after = now + Duration::days(VALIDITY_DAYS);

    let mut ca = CertificateParams::new(Vec::<String>::new())?;
    ca.distinguished_name = DistinguishedName::new();
    ca.distinguished_name
        .push(DnType::CommonName, "Riggs mail bridge local CA");
    (ca.not_before, ca.not_after) = (now, not_after);
    ca.is_ca = IsCa::Ca(BasicConstraints::Constrained(0));
    ca.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    ca.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    ca.name_constraints = Some(NameConstraints {
        permitted_subtrees: vec![
            GeneralSubtree::DnsName("localhost".into()),
            GeneralSubtree::IpAddress(CidrSubnet::V4([127, 0, 0, 1], [255; 4])),
        ],
        excluded_subtrees: vec![],
    });
    let ca_key = KeyPair::generate()?;
    let ca_pem = ca.self_signed(&ca_key)?.pem();
    let issuer = Issuer::new(ca, ca_key);

    let mut leaf = CertificateParams::new(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    leaf.distinguished_name = DistinguishedName::new();
    leaf.distinguished_name
        .push(DnType::CommonName, "localhost");
    (leaf.not_before, leaf.not_after) = (now, not_after);
    leaf.is_ca = IsCa::ExplicitNoCa;
    leaf.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    leaf.use_authority_key_identifier_extension = true;
    let leaf_key = KeyPair::generate()?;
    let leaf_pem = leaf.signed_by(&leaf_key, &issuer)?.pem();
    Ok((ca_pem, leaf_pem, leaf_key.serialize_pem()))
}

fn read_if_present(path: &Path) -> anyhow::Result<Option<String>> {
    match fs::read_to_string(path) {
        Ok(text) => Ok(Some(text)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| format!("cannot read {}", path.display())),
    }
}

fn write_private(path: &Path, contents: &str) -> anyhow::Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    file.set_permissions(Permissions::from_mode(0o600))?;
    Ok(file.write_all(contents.as_bytes())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::server::tests::write_assets;
    use x509_parser::extensions::GeneralName;
    use x509_parser::oid_registry::{
        OID_EC_P256, OID_KEY_TYPE_EC_PUBLIC_KEY, OID_SIG_ECDSA_WITH_SHA256,
    };
    use x509_parser::prelude::parse_x509_certificate;

    const FILES: [&str; 6] = [
        "token",
        "port",
        "key.pem",
        "cert.pem",
        "ca.pem",
        "manifest.xml",
    ];

    fn dirs() -> (tempfile::TempDir, std::path::PathBuf, std::path::PathBuf) {
        let tmp = tempfile::tempdir().unwrap();
        let (state, assets) = (tmp.path().join("state"), tmp.path().join("assets"));
        write_assets(&assets);
        (tmp, state, assets)
    }

    fn snapshot(state: &Path) -> Vec<Vec<u8>> {
        FILES
            .iter()
            .map(|name| fs::read(state.join(name)).unwrap())
            .collect()
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    fn pem_ders(path: &Path) -> Vec<CertificateDer<'static>> {
        CertificateDer::pem_file_iter(path)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    #[test]
    fn setup_writes_private_files_a_complete_manifest_and_the_two_user_steps() {
        let (_tmp, state, assets) = dirs();
        let printed = setup(&state, &assets, Some(41500), false).unwrap();

        assert_eq!(mode(&state), 0o700);
        for name in FILES {
            assert_eq!(mode(&state.join(name)), 0o600, "{name}");
        }
        let token = fs::read_to_string(state.join("token")).unwrap();
        assert!(is_token(&token), "{token}");
        assert_eq!(fs::read_to_string(state.join("port")).unwrap(), "41500");
        let manifest = fs::read_to_string(state.join("manifest.xml")).unwrap();
        assert_eq!(
            manifest,
            format!("<Url>https://localhost:41500/{token}/taskpane.html</Url>")
        );

        let state = state.canonicalize().unwrap();
        let trust = format!(
            "security add-trusted-cert -r trustRoot -p ssl -k \"$HOME/Library/Keychains/login.keychain-db\" '{}'",
            state.join("ca.pem").display()
        );
        assert!(printed.contains(&trust), "{printed}");
        assert!(printed.contains(&format!("\n   {}\n", state.join("manifest.xml").display())));
        assert!(printed.contains("https://aka.ms/olksideload"));
        assert!(
            printed.contains("Certificate: new, valid for 799 more days."),
            "{printed}"
        );
    }

    #[test]
    fn certificates_meet_apples_rules_for_tls_servers_and_the_ca_is_constrained() {
        let (_tmp, state, assets) = dirs();
        setup(&state, &assets, None, false).unwrap();
        let chain = pem_ders(&state.join("cert.pem"));
        let ca_der = pem_ders(&state.join("ca.pem"));
        assert_eq!(chain.len(), 2);
        assert_eq!(ca_der, chain[1..]);
        let (_, leaf) = parse_x509_certificate(&chain[0]).unwrap();
        let (_, ca) = parse_x509_certificate(&chain[1]).unwrap();

        for cert in [&leaf, &ca] {
            let validity = cert.validity();
            assert!(validity.is_valid());
            let lifetime = (validity.not_after - validity.not_before).unwrap();
            assert!(lifetime <= Duration::days(825), "{lifetime}");
            assert_eq!(
                cert.signature_algorithm.algorithm,
                OID_SIG_ECDSA_WITH_SHA256
            );
            let key = &cert.public_key().algorithm;
            assert_eq!(key.algorithm, OID_KEY_TYPE_EC_PUBLIC_KEY);
            assert_eq!(
                key.parameters.as_ref().unwrap().as_oid().unwrap(),
                OID_EC_P256
            );
            let eku = cert.extended_key_usage().unwrap().unwrap().value;
            assert!(eku.server_auth && !eku.any && !eku.client_auth);
        }

        assert_eq!(leaf.issuer(), ca.subject());
        let names = &leaf.subject_alternative_name().unwrap().unwrap().value;
        assert_eq!(
            names.general_names,
            [
                GeneralName::DNSName("localhost"),
                GeneralName::IPAddress(&[127, 0, 0, 1])
            ]
        );
        assert!(!leaf.basic_constraints().unwrap().unwrap().value.ca);
        let usage = leaf.key_usage().unwrap().unwrap().value;
        assert!(usage.digital_signature() && !usage.key_cert_sign());

        let constraints = ca.basic_constraints().unwrap().unwrap().value;
        assert!(constraints.ca);
        assert_eq!(constraints.path_len_constraint, Some(0));
        let usage = ca.key_usage().unwrap().unwrap().value;
        assert!(usage.key_cert_sign() && usage.crl_sign() && !usage.digital_signature());
        let constraints = ca.name_constraints().unwrap().unwrap().value;
        assert!(constraints.excluded_subtrees.is_none());
        let permitted: Vec<_> = constraints
            .permitted_subtrees
            .iter()
            .flatten()
            .map(|subtree| &subtree.base)
            .collect();
        assert_eq!(
            permitted,
            [
                &GeneralName::DNSName("localhost"),
                &GeneralName::IPAddress(&[127, 0, 0, 1, 255, 255, 255, 255])
            ]
        );
    }

    #[test]
    fn a_second_run_changes_nothing_and_renew_replaces_token_and_certificate() {
        let (_tmp, state, assets) = dirs();
        let first = setup(&state, &assets, Some(41500), false).unwrap();
        let before = snapshot(&state);

        let second = setup(&state, &assets, None, false).unwrap();
        assert_eq!(snapshot(&state), before);
        assert!(first.contains("Certificate: new,") && second.contains("Certificate: unchanged,"));

        setup(&state, &assets, None, true).unwrap();
        let after = snapshot(&state);
        for (index, name) in FILES.iter().enumerate() {
            assert_eq!(before[index] == after[index], *name == "port", "{name}");
        }
    }

    #[test]
    fn a_certificate_within_30_days_of_expiry_is_replaced_and_the_token_kept() {
        let (_tmp, state, assets) = dirs();
        setup(&state, &assets, None, false).unwrap();
        let token = fs::read(state.join("token")).unwrap();
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
        params.not_before = OffsetDateTime::now_utc() - Duration::days(1);
        params.not_after = OffsetDateTime::now_utc() + Duration::days(29);
        fs::write(
            state.join("cert.pem"),
            params.self_signed(&key).unwrap().pem(),
        )
        .unwrap();

        setup(&state, &assets, None, false).unwrap();
        let left = time_left(&state.join("cert.pem")).unwrap().unwrap();
        assert!(left > Duration::days(VALIDITY_DAYS - 1), "{left}");
        assert_eq!(fs::read(state.join("token")).unwrap(), token);
    }

    #[test]
    fn a_template_without_the_token_or_with_another_placeholder_is_refused() {
        let (_tmp, state, assets) = dirs();
        for template in ["https://localhost:{{PORT}}/", "{{TOKEN}} {{ORIGIN}}"] {
            fs::write(assets.join("manifest.template.xml"), template).unwrap();
            assert!(setup(&state, &assets, None, false).is_err(), "{template}");
        }
    }
}
