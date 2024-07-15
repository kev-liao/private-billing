//use divtokens::voprf::{
//    advertiser::Advertiser,
//    messages::{
//        IssueResponse,
//        WinNotice,
//    },
//};
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
//    let req = advertiser.create_tokens(10);
//
//    let mut buf = Vec::new();
//    File::open("config/rootCA.pem")?
//        .read_to_end(&mut buf)?;
//    let cert = reqwest::Certificate::from_pem(&buf)?;
//
//    let cb = ClientBuilder::new()
//        .add_root_certificate(cert)
//        .build()?;
//    let resp = cb
//        .post("https://localhost:3030/issue")
//        .json(&req)
//        .send()
//        .await?;
//    
//    let resp = resp
//        .json::<IssueResponse>()
//        .await?;
//    
//    advertiser.store_signed_tokens(resp).unwrap();
//    
//    let win = WinNotice { price: 42 };
//    let req = advertiser.redeem_tokens(&win);
//    
//    let start = Instant::now();
//    
//    stream::iter((0..1000)
//                 .into_iter()
//                 .map(|_|
//                      async {
//                          let _ = cb.post("https://localhost:3030/redeem")
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
