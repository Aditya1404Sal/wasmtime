use futures::join;
use test_programs::p3::wasi::sockets::types::{
    IpAddress, IpAddressFamily, IpSocketAddress, TcpSocket,
};
use test_programs::p3::wit_stream;
use wit_bindgen::StreamResult;

struct Component;

test_programs::p3::export!(Component);

async fn test_smtp_ehlo() {
    println!("=== Gmail SMTP EHLO Test ===\n");

    let smtp_address = IpSocketAddress::new(
        IpAddress::Ipv4((74, 125, 200, 108)),
        587
    );

    println!("Connecting to Gmail SMTP server (smtp.gmail.com:587)...");
    
    let client = TcpSocket::create(IpAddressFamily::Ipv4).unwrap();
    client.connect(smtp_address).await.unwrap();
    
    println!("Connected!\n");

    let (mut data_tx, data_rx) = wit_stream::new();

    join!(
        // Send stream (keeps connection alive for writing)
        async {
            client.send(data_rx).await.unwrap();
            println!("Send stream completed");
        },
        async {
            let (mut client_rx, client_fut) = client.receive();
            
            println!("Waiting for server greeting...");
            let (result, greeting_data) = client_rx.read(Vec::with_capacity(512)).await;
            match result {
                StreamResult::Complete(n) if n > 0 => {
                    let greeting = String::from_utf8_lossy(&greeting_data);
                    println!("SERVER GREETING:");
                    println!("{}", greeting);
                    println!("{}", "=".repeat(50));
                }
                _ => {
                    println!("No greeting received: {:?}", result);
                    drop(data_tx);
                    drop(client_rx);
                    client_fut.await.ok();
                    return;
                }
            }
            
            // Send EHLO command
            let ehlo_cmd = b"EHLO localhost\r\n";
            println!("\nSENDING COMMAND: EHLO localhost");
            let remaining = data_tx.write_all(ehlo_cmd.to_vec()).await;
            assert!(remaining.is_empty());
            println!("{}", "=".repeat(50));
            
            // Read EHLO response - will be multiline
            println!("\nWaiting for EHLO response...");
            let (result, response_data) = client_rx.read(Vec::with_capacity(1024)).await;
            match result {
                StreamResult::Complete(n) if n > 0 => {
                    let response = String::from_utf8_lossy(&response_data);
                    println!("SERVER RESPONSE TO EHLO:");
                    println!("{}", response);
                    println!("{}", "=".repeat(50));
                }
                _ => {
                    println!("No EHLO response: {:?}", result);
                }
            }
            
            // Sending QUIT cmd
            let quit_cmd = b"QUIT\r\n";
            println!("\nSENDING COMMAND: QUIT");
            let remaining = data_tx.write_all(quit_cmd.to_vec()).await;
            assert!(remaining.is_empty());
            
            // Read QUIT response the 221 response
            println!("\nWaiting for QUIT response...");
            let (result, quit_data) = client_rx.read(Vec::with_capacity(256)).await;
            match result {
                StreamResult::Complete(n) if n > 0 => {
                    let quit_response = String::from_utf8_lossy(&quit_data);
                    println!("SERVER QUIT RESPONSE:");
                    println!("{}", quit_response);
                }
                _ => {
                    println!("No QUIT response: {:?}", result);
                }
            }
            
            drop(data_tx);
            drop(client_rx);
            client_fut.await.ok();
        }
    );

    println!("\nConnection closed cleanly");
}

impl test_programs::p3::exports::wasi::cli::run::Guest for Component {
    async fn run() -> Result<(), ()> {
        println!("Starting WASI P3 SMTP EHLO Test\n");
        
        test_smtp_ehlo().await;
        
        println!("\nTest completed!");
        Ok(())
    }
}

fn main() {}