//use divtokens::voprf::{
//    advertiser::Advertiser,
//    messages::{
//        IssueResponse,
//        WinNotice,
//    },
//};
//use parking_lot::RwLock;
//use reqwest::ClientBuilder;
//use std::{fs::File, io::Read, sync::Arc};
//use warp::Filter;
//
//async fn win(req: WinNotice,
//             advertiser: Advertiser)
//             -> Result<impl warp::Reply, warp::Rejection> {
//    let res = advertiser.redeem_tokens(&req);
//    Ok(warp::reply::json(&res))
//}
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
//    // TODO: bidrequest path
//    
//    let win = warp::path("win")
//        .and(warp::body::content_length_limit(1024 * 16))
//        .and(warp::body::json())
//        .and_then({
//            let advertiser = advertiser.clone();
//            move |req| win(req, advertiser.clone())
//        });
//
//    let routes = warp::post().and(win);
//
//    warp::serve(routes)
//        .tls()
//        .cert_path("config/advertiser-cert.pem")
//        .key_path("config/advertiser-key.pem")
//        .run(([127, 0, 0, 1], 3031))
//        .await;        
//    
//    Ok(())    
//}

fn main() {
}
