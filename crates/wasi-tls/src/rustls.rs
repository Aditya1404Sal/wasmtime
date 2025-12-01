use crate::{BoxFuture, TlsConnectionInfo, TlsProvider, TlsStream, TlsTransport};
use rustls::pki_types::ServerName;
use std::io;
use std::sync::{Arc, LazyLock};

impl crate::TlsStream for tokio_rustls::client::TlsStream<Box<dyn TlsTransport>> {}
impl crate::TlsStream for tokio_rustls::server::TlsStream<Box<dyn TlsTransport>> {}

/// The `rustls` provider.
pub struct RustlsProvider {
    client_config: Arc<rustls::ClientConfig>,
    server_config: Arc<rustls::ServerConfig>,
}

impl TlsProvider for RustlsProvider {
    fn connect(
        &self,
        server_name: String,
        transport: Box<dyn TlsTransport>,
    ) -> BoxFuture<io::Result<(Box<dyn TlsStream>, TlsConnectionInfo)>> {
        let client_config = Arc::clone(&self.client_config);

        Box::pin(async move {
            let domain = ServerName::try_from(server_name.as_str())
                .map_err(|_| io::Error::other("invalid server name"))?;

            let connector = tokio_rustls::TlsConnector::from(client_config);
            let stream = connector.connect(domain.to_owned(), transport).await?;

            //stub info currently, Needs a concrete way to get the below details
            let info = TlsConnectionInfo {
                cipher_suite: 0,
                peer_certificate: None,
                negotiated_alpn: None,
            };

            Ok((Box::new(stream) as Box<dyn TlsStream>, info))
        })
    }

    fn accept(
        &self,
        transport: Box<dyn TlsTransport>,
    ) -> BoxFuture<io::Result<(Box<dyn TlsStream>, TlsConnectionInfo)>> {
        let server_config = Arc::clone(&self.server_config);

        Box::pin(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let stream = acceptor.accept(transport).await?;

            //stub info currently, Needs a concrete way to get the below details
            let info = TlsConnectionInfo {
                cipher_suite: 0,
                peer_certificate: None,
                negotiated_alpn: None,
            };

            Ok((Box::new(stream) as Box<dyn TlsStream>, info))
        })
    }
}

impl RustlsProvider {
    /// Create a new `RustlsProvider` configured for client connections.
    pub fn client() -> Self {
        static CLIENT_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.into(),
            };
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(config)
        });

        Self {
            client_config: Arc::clone(&CLIENT_CONFIG),
            server_config: Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![],
                        rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into()),
                    )
                    .unwrap(),
            ),
        }
    }

    /// Create a new `RustlsProvider` configured for server connections.
    pub fn server() -> Self {
        static SERVER_CONFIG: LazyLock<Arc<rustls::ServerConfig>> = LazyLock::new(|| {
            // Default server config - applications should provide their own certificates
            let config = rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(
                    vec![],
                    rustls::pki_types::PrivateKeyDer::Pkcs8(vec![].into()),
                )
                .expect("Failed to create default server config");
            Arc::new(config)
        });

        static CLIENT_CONFIG: LazyLock<Arc<rustls::ClientConfig>> = LazyLock::new(|| {
            let roots = rustls::RootCertStore {
                roots: webpki_roots::TLS_SERVER_ROOTS.into(),
            };
            let config = rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth();
            Arc::new(config)
        });

        Self {
            client_config: Arc::clone(&CLIENT_CONFIG),
            server_config: Arc::clone(&SERVER_CONFIG),
        }
    }
}

impl Default for RustlsProvider {
    fn default() -> Self {
        Self::client()
    }
}
