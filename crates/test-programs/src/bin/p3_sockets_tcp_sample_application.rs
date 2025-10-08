use futures::join;
use test_programs::p3::wasi::sockets::types::{
    IpAddressFamily, IpSocketAddress, Ipv4SocketAddress, Ipv6SocketAddress, TcpSocket,
};
use test_programs::p3::wit_stream;
use test_programs::sockets::supports_ipv6;
use wit_bindgen::StreamResult;

struct Component;

test_programs::p3::export!(Component);

async fn test_tcp_sample_application(family: IpAddressFamily, bind_address: IpSocketAddress) {
    let first_message = b"Hello, world!";
    let second_message = b"Greetings, planet!";

    println!("Starting TCP test for {:?}", family);

    let listener = TcpSocket::create(family).unwrap();

    listener.bind(bind_address).unwrap();
    listener.set_listen_backlog_size(32).unwrap();
    let mut accept = listener.listen().unwrap();

    let addr = listener.get_local_address().unwrap();
    println!("Listening on: {:?}", addr);

    join!(
        async {
            println!("Client 1: Connecting...");
            let client = TcpSocket::create(family).unwrap();
            client.connect(addr).await.unwrap();
            println!("Client 1: Connected!");
            let (mut data_tx, data_rx) = wit_stream::new();
            join!(
                async {
                    client.send(data_rx).await.unwrap();
                    println!("Client 1: Finished sending data");
                },
                async {
                    let (result, _) = data_tx.write(vec![]).await;
                    assert_eq!(result, StreamResult::Complete(0));
                    let remaining = data_tx.write_all(first_message.into()).await;
                    assert!(remaining.is_empty());
                    println!("Client 1: Sent message: {:?}", String::from_utf8_lossy(first_message));
                    drop(data_tx);
                }
            );
        },
        async {
            println!("Server: Waiting for first connection...");
            let sock = accept.next().await.unwrap();
            println!("Server: Accepted first connection");
            
            let (mut data_rx, fut) = sock.receive();
            let (result, data) = data_rx.read(Vec::with_capacity(100)).await;
            assert_eq!(result, StreamResult::Complete(first_message.len()));
            println!("Server: Received message: {:?}", String::from_utf8_lossy(&data));
            // Check that we sent and received our message!
            assert_eq!(data, first_message); // Not guaranteed to work but should work in practice.

            let (result, data) = data_rx.read(Vec::with_capacity(1)).await;
            assert_eq!(result, StreamResult::Dropped);
            assert_eq!(data, []);

            fut.await.unwrap();
            println!("Server: First connection completed");
        },
    );

    // Another client
    join!(
        async {
            println!("Client 2: Connecting...");
            let client = TcpSocket::create(family).unwrap();
            client.connect(addr).await.unwrap();
            println!("Client 2: Connected!");
            let (mut data_tx, data_rx) = wit_stream::new();
            join!(
                async {
                    client.send(data_rx).await.unwrap();
                    println!("Client 2: Finished sending data");
                },
                async {
                    let remaining = data_tx.write_all(second_message.into()).await;
                    assert!(remaining.is_empty());
                    println!("Client 2: Sent message: {:?}", String::from_utf8_lossy(second_message));
                    drop(data_tx);
                }
            );
        },
        async {
            println!("Server: Waiting for second connection...");
            let sock = accept.next().await.unwrap();
            println!("Server: Accepted second connection");
            
            let (mut data_rx, fut) = sock.receive();
            let (result, data) = data_rx.read(Vec::with_capacity(100)).await;
            assert_eq!(result, StreamResult::Complete(second_message.len()));
            println!("Server: Received message: {:?}", String::from_utf8_lossy(&data));
            // Check that we sent and received our message!
            assert_eq!(data, second_message); // Not guaranteed to work but should work in practice.

            let (result, data) = data_rx.read(Vec::with_capacity(1)).await;
            assert_eq!(result, StreamResult::Dropped);
            assert_eq!(data, []);

            fut.await.unwrap();
            println!("Server: Second connection completed");
        }
    );
    
    println!("TCP test completed for {:?}", family);
}

impl test_programs::p3::exports::wasi::cli::run::Guest for Component {
    async fn run() -> Result<(), ()> {
        println!("Starting P3 sockets TCP sample application");
        
        test_tcp_sample_application(
            IpAddressFamily::Ipv4,
            IpSocketAddress::Ipv4(Ipv4SocketAddress {
                port: 0,                 // use any free port
                address: (127, 0, 0, 1), // localhost
            }),
        )
        .await;
        if supports_ipv6() {
            test_tcp_sample_application(
                IpAddressFamily::Ipv6,
                IpSocketAddress::Ipv6(Ipv6SocketAddress {
                    port: 0,                           // use any free port
                    address: (0, 0, 0, 0, 0, 0, 0, 1), // localhost
                    flow_info: 0,
                    scope_id: 0,
                }),
            )
            .await;
        }
        
        println!("All tests completed successfully!");
        Ok(())
    }
}

fn main() {}
