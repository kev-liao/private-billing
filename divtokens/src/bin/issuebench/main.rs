//use divtokens::voprf::advertiser::Advertiser;
//use futures::stream::{self, StreamExt};
//use parking_lot::RwLock;
//use reqwest::ClientBuilder;
//use std::{fs::File, io::Read, sync::Arc, time::Instant};
//
//#[tokio::main]
//async fn main() -> Result<(), Box<dyn std::error::Error>> {
//    let mut advertiser = Advertiser {
//        tokens: Arc::new(RwLock::new(Vec::new())),
//        blinded_tokens: Arc::new(RwLock::new(Vec::new())),
//        unblinded_tokens: Arc::new(RwLock::new(Vec::new())),
//    };
//    
//    let req = advertiser.create_tokens(100);
//
//    let mut buf = Vec::new();
//    File::open("config/rootCA.pem")?
//        .read_to_end(&mut buf)?;
//    let cert = reqwest::Certificate::from_pem(&buf)?;
//
//    let cb = ClientBuilder::new()
//        .add_root_certificate(cert)
//        .build()?;
//
//    let start = Instant::now();
//
//    stream::iter((0..10000)
//                 .into_iter()
//                 .map(|_|
//                      async {
//                          let _ = cb.post("https://localhost:3030/issue")
//                              .json(&req)
//                              .send()
//                              .await;
//                      })
//                )
//        .buffer_unordered(8)
//        .collect::<Vec<()>>()
//        .await;
//    
//    println!("Time elapsed: {:?}", start.elapsed());    
//    
//    Ok(())    
//}

fn main () {
}
