use anyhow::Result;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use wasmtime::component::Resource;
use wasmtime_wasi::p2::{DynInputStream, DynOutputStream, DynPollable};

use crate::{
    WasiTls, bindings,
    io::{
        AsyncReadStream, AsyncWriteStream, FutureOutput, WasiFuture, WasiStreamReader,
        WasiStreamWriter,
    },
};

use bindings::types::{
    Certificate, CipherSuite, Client, ClientResult, Connection, ErrorCode, InputStream,
    OutputStream, PrivateIdentity, Server, ServerResult,
};

use wasmtime_wasi::async_trait;
use wasmtime_wasi::p2::Pollable;

impl<'a> bindings::types::Host for WasiTls<'a> {}

use crate::TlsConnectionInfo;

pub struct HostClient {
    pub server_name: String,
    pub transport_input: Resource<InputStream>,
    pub transport_output: Resource<OutputStream>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub identity: Option<Resource<PrivateIdentity>>,
    pub state: ClientState,
    future:
        Option<WasiFuture<Result<(DynInputStream, DynOutputStream, TlsConnectionInfo), ErrorCode>>>,
}

pub enum ClientState {
    Configuring,
    Complete,
    Closed,
}

impl<'a> bindings::types::HostClient for WasiTls<'a> {
    fn new(
        &mut self,
        server_name: String,
        transport_input: Resource<InputStream>,
        transport_output: Resource<OutputStream>,
    ) -> wasmtime::Result<Result<Resource<Client>, ErrorCode>> {
        if server_name.is_empty() {
            return Ok(Err(ErrorCode::HostnameMismatch));
        }

        if !self.table.get::<DynInputStream>(&transport_input).is_ok() {
            return Ok(Err(ErrorCode::InternalError));
        }
        if !self.table.get::<DynOutputStream>(&transport_output).is_ok() {
            return Ok(Err(ErrorCode::InternalError));
        }

        let client = HostClient {
            server_name,
            transport_input,
            transport_output,
            alpn_protocols: vec![],
            identity: None,
            state: ClientState::Configuring,
            future: None,
        };

        let resource = self.table.push(client)?;
        Ok(Ok(resource))
    }

    fn set_alpn_protocols(
        &mut self,
        self_: Resource<Client>,
        protocols: Vec<String>,
    ) -> wasmtime::Result<Result<(), ()>> {
        let client = self.table.get_mut(&self_)?;

        if !matches!(client.state, ClientState::Configuring) {
            return Ok(Err(()));
        }

        if protocols.is_empty() {
            return Ok(Err(()));
        }

        client.alpn_protocols = protocols.into_iter().map(|p| p.into_bytes()).collect();

        Ok(Ok(()))
    }

    fn set_identity(
        &mut self,
        self_: Resource<Client>,
        identity: Resource<PrivateIdentity>,
    ) -> wasmtime::Result<Result<(), ()>> {
        if !self.table.get::<HostPrivateIdentity>(&identity).is_ok() {
            return Ok(Err(()));
        }

        let client = self.table.get_mut(&self_)?;

        if !matches!(client.state, ClientState::Configuring) {
            return Ok(Err(()));
        }

        client.identity = Some(identity);
        Ok(Ok(()))
    }

    /// MOST IMPORTANT PART - Initiates async TLS handshake
    fn finish(
        &mut self,
        self_: Resource<Client>,
    ) -> wasmtime::Result<Result<ClientResult, ErrorCode>> {
        let client = self.table.get_mut(&self_)?;

        if !matches!(client.state, ClientState::Configuring) {
            return Ok(Err(ErrorCode::InternalError));
        }

        // Check if future already exists (finish called multiple times)
        if let Some(ref mut future) = client.future {
            return match future.get() {
                FutureOutput::Ready(Ok((input, output, conn_info))) => {
                    // Create certificate resource if we have one
                    let peer_cert_res = if let Some(cert) = conn_info.peer_certificate {
                        let host_cert = HostCertificate::new(cert);
                        Some(self.table.push(host_cert)?)
                    } else {
                        None
                    };

                    let input_res = self.table.push(input)?;
                    let output_res = self.table.push(output)?;

                    // Create connection resource (store references to streams for cleanup)
                    let connection = HostConnection {
                        cipher_suite: conn_info.cipher_suite,
                        peer_certificate: peer_cert_res,
                        negotiated_alpn: conn_info.negotiated_alpn,
                        input: Resource::new_own(input_res.rep()),
                        output: Resource::new_own(output_res.rep()),
                        closed: false,
                    };

                    let connection_res = self.table.push(connection)?;

                    // Update client state
                    let client = self.table.get_mut(&self_)?;
                    client.state = ClientState::Complete;

                    Ok(Ok(ClientResult {
                        connection: connection_res,
                        input: input_res,
                        output: output_res,
                    }))
                }
                FutureOutput::Ready(Err(error_code)) => Ok(Err(error_code)),
                FutureOutput::Pending => Ok(Err(ErrorCode::WouldBlock)),
                FutureOutput::Consumed => Ok(Err(ErrorCode::InternalError)),
            };
        }

        // First call to finish - start the async handshake
        let transport_input =
            std::mem::replace(&mut client.transport_input, Resource::new_borrow(0));
        let transport_output =
            std::mem::replace(&mut client.transport_output, Resource::new_borrow(0));
        let server_name = client.server_name.clone();

        // Delete the transport streams
        let transport_input = self.table.delete(transport_input)?;
        let transport_output = self.table.delete(transport_output)?;

        // Convert WASI streams to AsyncRead/AsyncWrite
        let reader = WasiStreamReader::new(transport_input);
        let writer = WasiStreamWriter::new(transport_output);
        let transport = tokio::io::join(reader, writer);

        // Spawn async handshake
        let connect_future = self
            .ctx
            .client_provider
            .connect(server_name, Box::new(transport));

        let future = WasiFuture::spawn(async move {
            let (tls_stream, conn_info) = connect_future
                .await
                .map_err(|_| ErrorCode::HandshakeFailure)?;

            // Split TLS stream into read/write halves
            let (rx, tx) = tokio::io::split(tls_stream);

            // Wrap in WASI streams
            let input = Box::new(AsyncReadStream::new(rx)) as DynInputStream;
            let output = Box::new(AsyncWriteStream::new(tx)) as DynOutputStream;

            Ok((input, output, conn_info))
        });

        // Store future and return would-block
        let client = self.table.get_mut(&self_)?;
        client.future = Some(future);

        Ok(Err(ErrorCode::WouldBlock))
    }

    /// Subscribe to the async handshake completion
    fn subscribe(&mut self, self_: Resource<Client>) -> wasmtime::Result<Resource<DynPollable>> {
        wasmtime_wasi::p2::subscribe(self.table, self_)
    }

    fn drop(&mut self, rep: Resource<Client>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

#[async_trait]
impl Pollable for HostClient {
    async fn ready(&mut self) {
        if let Some(ref mut future) = self.future {
            future.ready().await;
        }
    }
}

pub struct HostServer {
    pub transport_input: Resource<InputStream>,
    pub transport_output: Resource<OutputStream>,
    pub identity: Option<Resource<PrivateIdentity>>,
    pub alpn_protocols: Vec<Vec<u8>>,
    pub client_auth_required: bool,
    pub state: ServerState,
    future:
        Option<WasiFuture<Result<(DynInputStream, DynOutputStream, TlsConnectionInfo), ErrorCode>>>,
}

pub enum ServerState {
    Configuring,
    Complete,
    Closed,
}

impl<'a> bindings::types::HostServer for WasiTls<'a> {
    fn new(
        &mut self,
        transport_input: Resource<InputStream>,
        transport_output: Resource<OutputStream>,
    ) -> wasmtime::Result<Result<Resource<Server>, ErrorCode>> {
        if !self.table.get::<DynInputStream>(&transport_input).is_ok() {
            return Ok(Err(ErrorCode::InternalError));
        }
        if !self.table.get::<DynOutputStream>(&transport_output).is_ok() {
            return Ok(Err(ErrorCode::InternalError));
        }

        let server = HostServer {
            transport_input,
            transport_output,
            identity: None,
            alpn_protocols: vec![],
            client_auth_required: false,
            state: ServerState::Configuring,
            future: None,
        };

        let resource = self.table.push(server)?;
        Ok(Ok(resource))
    }

    fn set_identity(
        &mut self,
        self_: Resource<Server>,
        identity: Resource<PrivateIdentity>,
    ) -> wasmtime::Result<Result<(), ()>> {
        if !self.table.get::<HostPrivateIdentity>(&identity).is_ok() {
            return Ok(Err(()));
        }

        let server = self.table.get_mut(&self_)?;

        if !matches!(server.state, ServerState::Configuring) {
            return Ok(Err(()));
        }

        server.identity = Some(identity);
        Ok(Ok(()))
    }

    fn set_alpn_protocols(
        &mut self,
        self_: Resource<Server>,
        protocols: Vec<String>,
    ) -> wasmtime::Result<Result<(), ()>> {
        let server = self.table.get_mut(&self_)?;

        if !matches!(server.state, ServerState::Configuring) {
            return Ok(Err(()));
        }

        if protocols.is_empty() {
            return Ok(Err(()));
        }

        server.alpn_protocols = protocols.into_iter().map(|p| p.into_bytes()).collect();

        Ok(Ok(()))
    }

    fn set_client_auth_required(
        &mut self,
        self_: Resource<Server>,
        required: bool,
    ) -> wasmtime::Result<Result<(), ()>> {
        let server = self.table.get_mut(&self_)?;

        if !matches!(server.state, ServerState::Configuring) {
            return Ok(Err(()));
        }

        server.client_auth_required = required;
        Ok(Ok(()))
    }

    fn finish(
        &mut self,
        self_: Resource<Server>,
    ) -> wasmtime::Result<Result<ServerResult, ErrorCode>> {
        let server = self.table.get_mut(&self_)?;

        if !matches!(server.state, ServerState::Configuring) {
            return Ok(Err(ErrorCode::InternalError));
        }

        // Server MUST have identity
        if server.identity.is_none() {
            return Ok(Err(ErrorCode::CertificateInvalid));
        }

        // Check if future already exists (finish called multiple times)
        if let Some(ref mut future) = server.future {
            return match future.get() {
                FutureOutput::Ready(Ok((input, output, conn_info))) => {
                    // Create certificate resource if we have one
                    let peer_cert_res = if let Some(cert) = conn_info.peer_certificate {
                        let host_cert = HostCertificate::new(cert);
                        Some(self.table.push(host_cert)?)
                    } else {
                        None
                    };

                    let input_res = self.table.push(input)?;
                    let output_res = self.table.push(output)?;

                    // Create connection resource (store references to streams for cleanup)
                    let connection = HostConnection {
                        cipher_suite: conn_info.cipher_suite,
                        peer_certificate: peer_cert_res,
                        negotiated_alpn: conn_info.negotiated_alpn,
                        input: Resource::new_own(input_res.rep()),
                        output: Resource::new_own(output_res.rep()),
                        closed: false,
                    };

                    let connection_res = self.table.push(connection)?;

                    // Update server state
                    let server = self.table.get_mut(&self_)?;
                    server.state = ServerState::Complete;

                    Ok(Ok(ServerResult {
                        connection: connection_res,
                        input: input_res,
                        output: output_res,
                    }))
                }
                FutureOutput::Ready(Err(error_code)) => Ok(Err(error_code)),
                FutureOutput::Pending => Ok(Err(ErrorCode::WouldBlock)),
                FutureOutput::Consumed => Ok(Err(ErrorCode::InternalError)),
            };
        }

        // First call to finish - start the async handshake
        let transport_input =
            std::mem::replace(&mut server.transport_input, Resource::new_borrow(0));
        let transport_output =
            std::mem::replace(&mut server.transport_output, Resource::new_borrow(0));

        // Delete the transport streams
        let transport_input = self.table.delete(transport_input)?;
        let transport_output = self.table.delete(transport_output)?;

        // Convert WASI streams to AsyncRead/AsyncWrite
        let reader = WasiStreamReader::new(transport_input);
        let writer = WasiStreamWriter::new(transport_output);
        let transport = tokio::io::join(reader, writer);

        // Spawn async handshake
        let accept_future = self.ctx.server_provider.accept(Box::new(transport));

        let future = WasiFuture::spawn(async move {
            let (tls_stream, conn_info) = accept_future
                .await
                .map_err(|_| ErrorCode::HandshakeFailure)?;

            // Split TLS stream into read/write halves
            let (rx, tx) = tokio::io::split(tls_stream);

            // Wrap in WASI streams
            let input = Box::new(AsyncReadStream::new(rx)) as DynInputStream;
            let output = Box::new(AsyncWriteStream::new(tx)) as DynOutputStream;

            Ok((input, output, conn_info))
        });

        // Store future and return would-block
        let server = self.table.get_mut(&self_)?;
        server.future = Some(future);

        Ok(Err(ErrorCode::WouldBlock))
    }
    // Subscribe to the async handshake completion
    fn subscribe(&mut self, self_: Resource<Server>) -> wasmtime::Result<Resource<DynPollable>> {
        wasmtime_wasi::p2::subscribe(self.table, self_)
    }

    fn drop(&mut self, rep: Resource<Server>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

#[async_trait]
impl Pollable for HostServer {
    async fn ready(&mut self) {
        if let Some(ref mut future) = self.future {
            future.ready().await;
        }
    }
}

pub struct HostConnection {
    pub cipher_suite: u16,
    pub peer_certificate: Option<Resource<Certificate>>,
    pub negotiated_alpn: Option<Vec<u8>>,
    pub input: Resource<InputStream>,
    pub output: Resource<OutputStream>,
    pub closed: bool,
}

impl<'a> bindings::types::HostConnection for WasiTls<'a> {
    fn cipher_suite(&mut self, self_: Resource<Connection>) -> wasmtime::Result<CipherSuite> {
        let conn = self.table.get_mut(&self_)?;
        Ok(conn.cipher_suite)
    }

    fn peer_certificate(
        &mut self,
        self_: Resource<Connection>,
    ) -> wasmtime::Result<Option<Resource<Certificate>>> {
        let conn = self.table.get_mut(&self_)?;
        Ok(conn.peer_certificate.take())
    }

    fn close(&mut self, _self_: Resource<Connection>) -> wasmtime::Result<Result<(), ErrorCode>> {
        todo!()
    }

    fn drop(&mut self, rep: Resource<Connection>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

#[derive(Clone)]
pub struct HostCertificate {
    pub cert: CertificateDer<'static>,
    pub parsed: Option<x509_parser::certificate::X509Certificate<'static>>,
}

impl HostCertificate {
    pub fn new(cert: CertificateDer<'static>) -> Self {
        Self { cert, parsed: None }
    }

    pub fn get_parsed(&mut self) -> Result<&x509_parser::certificate::X509Certificate<'static>> {
        if self.parsed.is_none() {
            let boxed = self.cert.as_ref().to_vec().into_boxed_slice();
            let leaked: &'static [u8] = Box::leak(boxed);
            let (_, parsed) = x509_parser::parse_x509_certificate(leaked)?;
            self.parsed = Some(parsed);
        }
        Ok(self.parsed.as_ref().unwrap())
    }
}

impl<'a> bindings::types::HostCertificate for WasiTls<'a> {
    fn subject(&mut self, self_: Resource<Certificate>) -> wasmtime::Result<String> {
        let cert = self.table.get_mut(&self_)?;
        let parsed = cert
            .get_parsed()
            .map_err(|e| wasmtime::Error::msg(format!("Failed to parse certificate: {}", e)))?;
        Ok(parsed.subject().to_string())
    }

    fn issuer(&mut self, self_: Resource<Certificate>) -> wasmtime::Result<String> {
        let cert = self.table.get_mut(&self_)?;
        let parsed = cert
            .get_parsed()
            .map_err(|e| wasmtime::Error::msg(format!("Failed to parse certificate: {}", e)))?;
        Ok(parsed.issuer().to_string())
    }

    fn verify_hostname(
        &mut self,
        self_: Resource<Certificate>,
        hostname: String,
    ) -> wasmtime::Result<bool> {
        let cert = self.table.get_mut(&self_)?;
        let parsed = cert
            .get_parsed()
            .map_err(|e| wasmtime::Error::msg(format!("Failed to parse certificate: {}", e)))?;

        // Check Common Name
        if let Some(cn) = parsed.subject().iter_common_name().next() {
            if let Ok(cn_str) = cn.as_str() {
                if cn_str == hostname {
                    return Ok(true);
                }
            }
        }

        // Check Subject Alternative Names
        if let Ok(Some(san_ext)) = parsed.subject_alternative_name() {
            for name in &san_ext.value.general_names {
                if let x509_parser::extensions::GeneralName::DNSName(dns) = name {
                    if *dns == hostname {
                        return Ok(true);
                    }
                }
            }
        }

        Ok(false)
    }

    fn drop(&mut self, rep: Resource<Certificate>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}

pub struct HostPrivateIdentity {
    pub cert_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

impl<'a> bindings::types::HostPrivateIdentity for WasiTls<'a> {
    fn certificate(
        &mut self,
        self_: Resource<PrivateIdentity>,
    ) -> wasmtime::Result<Resource<Certificate>> {
        let identity = self.table.get(&self_)?;

        // Return the first (leaf) certificate
        let cert = identity
            .cert_chain
            .first()
            .ok_or_else(|| wasmtime::Error::msg("No certificate in chain"))?
            .clone();

        let host_cert = HostCertificate::new(cert);
        let resource = self.table.push(host_cert)?;
        Ok(resource)
    }

    fn drop(&mut self, rep: Resource<PrivateIdentity>) -> wasmtime::Result<()> {
        self.table.delete(rep)?;
        Ok(())
    }
}
