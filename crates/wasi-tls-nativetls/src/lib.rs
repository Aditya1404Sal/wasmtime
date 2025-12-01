//! The `native_tls` provider.

use std::{future::Future, io, pin::pin, sync::Arc};

use wasmtime_wasi_tls::{TlsConnectionInfo, TlsProvider, TlsStream, TlsTransport};

type BoxFuture<T> = std::pin::Pin<Box<dyn Future<Output = T> + Send>>;

/// The `native_tls` provider.
pub struct NativeTlsProvider {
    client_config: Arc<tokio_native_tls::native_tls::TlsConnectorBuilder>,
}

impl TlsProvider for NativeTlsProvider {
    fn connect(
        &self,
        server_name: String,
        transport: Box<dyn TlsTransport>,
    ) -> BoxFuture<io::Result<(Box<dyn TlsStream>, TlsConnectionInfo)>> {
        // clone the config up-front so the async future doesn't capture `&self`
        let client_config = Arc::clone(&self.client_config);

        let connect_impl = move |server_name: String, transport: Box<dyn TlsTransport>| async move {
            // if needed, use the cloned config inside the async block
            let _client_config = Arc::clone(&client_config);

            let connector = native_tls::TlsConnector::new()?;
            let stream = tokio_native_tls::TlsConnector::from(connector)
                .connect(&server_name, transport)
                .await?;
            Ok::<NativeTlsStream, native_tls::Error>(NativeTlsStream(stream))
        };

        let info = TlsConnectionInfo {
            cipher_suite: 0,
            peer_certificate: None,
            negotiated_alpn: None,
        };

        Box::pin(async move {
            let stream = connect_impl(server_name, transport)
                .await
                .map_err(|e| io::Error::other(e))?;
            Ok((Box::new(stream) as Box<dyn TlsStream>, info))
        })
    }

    fn accept(
        &self,
        _transport: Box<dyn TlsTransport>,
    ) -> BoxFuture<io::Result<(Box<dyn TlsStream>, TlsConnectionInfo)>> {
        // Native TLS server functionality would need native_tls::TlsAcceptor
        // For now, return an error since native-tls server setup requires certificates
        Box::pin(async move {
            Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "Server-side TLS not implemented for native-tls provider",
            ))
        })
    }
}

impl Default for NativeTlsProvider {
    fn default() -> Self {
        Self {
            client_config: Arc::new(tokio_native_tls::native_tls::TlsConnector::builder()),
        }
    }
}

struct NativeTlsStream(tokio_native_tls::TlsStream<Box<dyn TlsTransport>>);

impl TlsStream for NativeTlsStream {}

impl tokio::io::AsyncRead for NativeTlsStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        pin!(&mut self.as_mut().0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for NativeTlsStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        pin!(&mut self.as_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        pin!(&mut self.as_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        pin!(&mut self.as_mut().0).poll_shutdown(cx)
    }
}
