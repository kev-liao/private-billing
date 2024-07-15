//use divtokens::voprf::messages::{RedeemRequest, RedeemResponse};
//use reqwest::ClientBuilder;
//use std::{fs::File, io::Read};
//use warp::Filter;
//
//async fn redeem(req: RedeemRequest)
//              -> Result<impl warp::Reply, warp::Rejection> {
//    let mut buf = Vec::new();
//    File::open("config/rootCA.pem")
//        .unwrap()
//        .read_to_end(&mut buf)
//        .unwrap();
//    let cert = reqwest::Certificate::from_pem(&buf).unwrap();
//    
//    let cb = ClientBuilder::new()
//        .add_root_certificate(cert)
//        .build()
//        .unwrap();
//    let res = cb
//        .post("https://localhost:3030/redeem")
//        .json(&req)
//        .send()
//        .await;
//
//    match res {
//        Ok(r) => {
//            let res = r
//                .json::<RedeemResponse>()
//                .await
//                .unwrap();
//            Ok(warp::reply::json(&res))            
//        },
//        Err(_) => Err(warp::reject())
//    }
//}
//
//#[tokio::main]
//async fn main() -> Result<(), Box<dyn std::error::Error>> {
//    
//    let redeem = warp::path("redeem")
//        .and(warp::body::content_length_limit(1024 * 16))
//        .and(warp::body::json())
//        .and_then(redeem);
//
//    let routes = warp::post().and(redeem);
//
//    warp::serve(routes)
//        .tls()
//        .cert_path("config/publisher-cert.pem")
//        .key_path("config/publisher-key.pem")
//        .run(([127, 0, 0, 1], 3032))
//        .await;    
//    
//    Ok(())    
//}

fn main() {
}
