//! Auto-generated bindings.

#[expect(missing_docs, reason = "bindgen-generated code")]
mod generated {
    wasmtime::component::bindgen!({
        path: "wit",
        world: "wasi:tls/imports",
        with: {
            "wasi:io": wasmtime_wasi::p2::bindings::io,
            "wasi:tls/types.certificate": crate::HostCertificate,
            "wasi:tls/types.private-identity": crate::HostPrivateIdentity,
            "wasi:tls/types.connection": crate::HostConnection,
            "wasi:tls/types.client" : crate::HostClient,
            "wasi:tls/types.server" : crate::HostServer,
        },
        imports: { default: trappable },
        require_store_data_send: true,
    });
}

pub use generated::wasi::tls::*;
