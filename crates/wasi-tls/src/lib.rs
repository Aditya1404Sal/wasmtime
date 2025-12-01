use tokio::io::{AsyncRead, AsyncWrite};
use tokio_rustls::rustls::pki_types::CertificateDer;
use wasmtime::component::{HasData, ResourceTable};

pub mod bindings;
mod host;
mod io;
mod rustls;

pub use host::{HostCertificate, HostClient, HostConnection, HostPrivateIdentity, HostServer};
pub use rustls::RustlsProvider;

/// Capture the state necessary for use in the `wasi-tls` API implementation.
pub struct WasiTls<'a> {
    ctx: &'a WasiTlsCtx,
    table: &'a mut ResourceTable,
}

impl<'a> WasiTls<'a> {
    /// Create a new Wasi TLS context
    pub fn new(ctx: &'a WasiTlsCtx, table: &'a mut ResourceTable) -> Self {
        Self { ctx, table }
    }
}

/// Add the `wasi-tls` world's types to a [`wasmtime::component::Linker`].
pub fn add_to_linker<T: Send + 'static>(
    l: &mut wasmtime::component::Linker<T>,
    f: fn(&mut T) -> WasiTls<'_>,
) -> anyhow::Result<()> {
    bindings::types::add_to_linker::<_, HasWasiTls>(l, f)?;
    Ok(())
}

struct HasWasiTls;
impl HasData for HasWasiTls {
    type Data<'a> = WasiTls<'a>;
}

/// Builder-style structure used to create a [`WasiTlsCtx`].
pub struct WasiTlsCtxBuilder {
    client_provider: Box<dyn TlsProvider>,
    server_provider: Box<dyn TlsProvider>,
}

impl WasiTlsCtxBuilder {
    /// Creates a builder for a new context with default parameters set.
    pub fn new() -> Self {
        Default::default()
    }

    /// Configure the TLS provider to use for this context.
    pub fn client_provider(mut self, client_provider: Box<dyn TlsProvider>) -> Self {
        self.client_provider = client_provider;
        self
    }

    pub fn server_provider(mut self, server_provider: Box<dyn TlsProvider>) -> Self {
        self.server_provider = server_provider;
        self
    }

    /// Uses the configured context so far to construct the final [`WasiTlsCtx`].
    pub fn build(self) -> WasiTlsCtx {
        WasiTlsCtx {
            client_provider: self.client_provider,
            server_provider: self.server_provider,
        }
    }
}

impl Default for WasiTlsCtxBuilder {
    fn default() -> Self {
        Self {
            client_provider: Box::new(RustlsProvider::client()),
            server_provider: Box::new(RustlsProvider::server()),
        }
    }
}

/// Wasi TLS context needed for internal `wasi-tls` state.
pub struct WasiTlsCtx {
    pub(crate) client_provider: Box<dyn TlsProvider>,
    pub(crate) server_provider: Box<dyn TlsProvider>,
}

/// The data stream that carries the encrypted TLS data.
pub trait TlsTransport: AsyncRead + AsyncWrite + Send + Unpin + 'static {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin + ?Sized + 'static> TlsTransport for T {}

/// A TLS connection.
pub trait TlsStream: AsyncRead + AsyncWrite + Send + Unpin + 'static {}

/// Information about an established TLS connection
pub struct TlsConnectionInfo {
    /// The negotiated cipher suite (as a u16 value)
    pub cipher_suite: u16,

    /// The peer's certificate (if any)
    pub peer_certificate: Option<CertificateDer<'static>>,

    /// The negotiated ALPN protocol (if any)
    pub negotiated_alpn: Option<Vec<u8>>,
}

/// A TLS implementation.
pub trait TlsProvider: Send + Sync + 'static {
    /// Set up a client TLS connection using the provided `server_name` and `transport`.
    /// Returns the TLS stream and connection information.
    fn connect(
        &self,
        server_name: String,
        transport: Box<dyn TlsTransport>,
    ) -> BoxFuture<std::io::Result<(Box<dyn TlsStream>, TlsConnectionInfo)>>;

    /// Accept a server TLS connection using the provided `transport`.
    /// Returns the TLS stream and connection information.
    fn accept(
        &self,
        transport: Box<dyn TlsTransport>,
    ) -> BoxFuture<std::io::Result<(Box<dyn TlsStream>, TlsConnectionInfo)>>;
}

pub(crate) type BoxFuture<T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send>>;
