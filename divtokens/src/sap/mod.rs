pub mod client;
pub mod server;
pub mod messages;

#[cfg(test)]
mod test {
    use ark_serialize::*;
    use bloomfilter::Bloom;    
    use challenge_bypass_ristretto::voprf::*;
    use parking_lot::RwLock;    
    use rand::rngs::OsRng;
    use serial_test::serial;    
    use std::{
        fs::{create_dir_all, File},
        time::{Duration, Instant},
        sync::Arc,
    };    

    use crate::sap::client::Client;
    use crate::sap::server::Server;
    use crate::sap::messages::WinNotice;

    #[test]
    #[serial]    
    fn sap_bench_client_issue_request() {
        create_dir_all("results/").unwrap();

        let mut comp_file = File::create("results/sap_issue_request_computation.dat").unwrap();
        comp_file.write_all(b"# Issue request computation\n").unwrap();
        comp_file.write_all(b"# Batch/wallet size vs. CPU time (ms)\n").unwrap();

        let mut comm_file = File::create("results/sap_issue_request_communication.dat").unwrap();
        comm_file.write_all(b"# Issue request communication\n").unwrap();
        comm_file.write_all(b"# Batch/wallet size vs. communication (bytes)\n").unwrap();
    
        let mut client = Client {
            tokens: Arc::new(RwLock::new(Vec::new())),
            blinded_tokens: Arc::new(RwLock::new(Vec::new())),
            unblinded_tokens: Arc::new(RwLock::new(Vec::new())),
        };

        const ITERS: u32 = 100;

        // Benchmark issue request
        let powers: Vec<u16> = (6..13).map(|x: u16| (1u16 << x)).collect();
        for batch_size in powers.iter() {
            println!("Batch size {:?}", batch_size);
            let mut duration = Duration::new(0, 0);
            for _ in 0..ITERS {
                let start = Instant::now();
                client.issue_request(*batch_size);
                duration += start.elapsed();
                // Reset state
                client.reset_state();
            }
            let avg_duration = duration.checked_div(ITERS).unwrap().as_millis();
            let issue_request = client.issue_request(*batch_size);
            let num_bytes = bincode::serialize(&issue_request).unwrap().len();
            comp_file.write_all(format!("{} {}\n", batch_size, avg_duration).as_bytes()).unwrap();
            comm_file.write_all(format!("{} {}\n", batch_size, num_bytes).as_bytes()).unwrap();
        }
    }

    #[test]
    #[serial]    
    fn sap_bench_server_issue_request() {
        create_dir_all("results/").unwrap();

        let mut comp_file = File::create("results/sap_issue_computation.dat").unwrap();
        comp_file.write_all(b"# Issue computation\n").unwrap();
        comp_file.write_all(b"# Batch/wallet size vs. CPU time (ms)\n").unwrap();

        let mut comm_file = File::create("results/sap_issue_communication.dat").unwrap();
        comm_file.write_all(b"# Issue communication\n").unwrap();
        comm_file.write_all(b"# Batch/wallet size vs. communication (bytes)\n").unwrap();

        let mut rng = OsRng;
        let signing_key = SigningKey::random(&mut rng);
        
        let mut client = Client {
            tokens: Arc::new(RwLock::new(Vec::new())),
            blinded_tokens: Arc::new(RwLock::new(Vec::new())),
            unblinded_tokens: Arc::new(RwLock::new(Vec::new())),
        };

        let server = Server {
            signing_key,
            //spent_tokens: Arc::new(RwLock::new(Vec::new())),
            bloom: Bloom::new_for_fp_rate(100000000, 0.000001),
        };

        const ITERS: u32 = 100;

        // Benchmark issue
        let powers: Vec<u16> = (6..13).map(|x: u16| (1u16 << x)).collect();
        for batch_size in powers.iter() {
            println!("Batch size {:?}", batch_size);            
            let mut duration = Duration::new(0, 0);
            for _ in 0..ITERS {
                let issue_request = client.issue_request(*batch_size);
                let start = Instant::now();
                server.issue(issue_request);
                duration += start.elapsed();
                // Reset state
                client.reset_state();                
            }
            let avg_duration = duration.checked_div(ITERS).unwrap().as_millis();
            let issue_request = client.issue_request(*batch_size);            
            let issue_response = server.issue(issue_request);
            let num_bytes = bincode::serialize(&issue_response).unwrap().len();
            comp_file.write_all(format!("{} {}\n", batch_size, avg_duration).as_bytes()).unwrap();
            comm_file.write_all(format!("{} {}\n", batch_size, num_bytes).as_bytes()).unwrap();
        }
    }

    #[test]
    #[serial]    
    fn sap_bench_client_issue_process() {
        create_dir_all("results/").unwrap();

        let mut comp_file = File::create("results/sap_issue_process_computation.dat").unwrap();
        comp_file.write_all(b"# Issue process computation\n").unwrap();
        comp_file.write_all(b"# Batch/wallet size vs. CPU time (ms)\n").unwrap();

        let mut rng = OsRng;
        let signing_key = SigningKey::random(&mut rng);
        
        let mut client = Client {
            tokens: Arc::new(RwLock::new(Vec::new())),
            blinded_tokens: Arc::new(RwLock::new(Vec::new())),
            unblinded_tokens: Arc::new(RwLock::new(Vec::new())),
        };

        let server = Server {
            signing_key,
            //spent_tokens: Arc::new(RwLock::new(Vec::new())),
            bloom: Bloom::new_for_fp_rate(100000000, 0.000001),
        };

        const ITERS: u32 = 100;

        // Benchmark issue
        let powers: Vec<u16> = (6..13).map(|x: u16| (1u16 << x)).collect();
        for batch_size in powers.iter() {
            println!("Batch size {:?}", batch_size);            
            let mut duration = Duration::new(0, 0);
            for _ in 0..ITERS {
                let issue_request = client.issue_request(*batch_size);
                let issue_response = server.issue(issue_request);
                let start = Instant::now();
                client.issue_process(issue_response).unwrap();
                duration += start.elapsed();
                // Reset state
                client.reset_state();                
            }
            let avg_duration = duration.checked_div(ITERS).unwrap().as_millis();
            comp_file.write_all(format!("{} {}\n", batch_size, avg_duration).as_bytes()).unwrap();
        }
    }

    #[test]
    #[serial]    
    fn sap_bench_client_redeem_request() {
        create_dir_all("results/").unwrap();

        let mut comm_file = File::create("results/sap_redeem_request_communication.dat").unwrap();
        comm_file.write_all(b"# Redeem request communication\n").unwrap();
        comm_file.write_all(b"# Value vs. communication (bytes)\n").unwrap();

        let mut rng = OsRng;
        let signing_key = SigningKey::random(&mut rng);
        
        let mut client = Client {
            tokens: Arc::new(RwLock::new(Vec::new())),
            blinded_tokens: Arc::new(RwLock::new(Vec::new())),
            unblinded_tokens: Arc::new(RwLock::new(Vec::new())),
        };

        let server = Server {
            signing_key,
            //spent_tokens: Arc::new(RwLock::new(Vec::new())),
            bloom: Bloom::new_for_fp_rate(100000000, 0.000001),
        };

        let issue_request = client.issue_request(1);
        let issue_response = server.issue(issue_request);
        client.issue_process(issue_response).unwrap();
        let win_notice = WinNotice { price: 42 };        
        let mut redeem_request = client.redeem_request(&win_notice);

        let coin = redeem_request.coins[0].clone();
        let coin_bytes = bincode::serialize(&coin).unwrap().len();
        redeem_request.coins = vec![];
        let req_bytes = bincode::serialize(&redeem_request).unwrap().len();
        for v in 1..=4096u32 {
            let hw = hamming::weight(&v.to_be_bytes());
            //let num_bytes = req_bytes + coin_bytes * (hw as usize);
            let num_bytes = ((req_bytes + coin_bytes * (hw as usize)) as f32) / 1024.0;
            comm_file.write_all(format!("{} {}\n", v, num_bytes).as_bytes()).unwrap();
        }
    }

    #[test]
    #[serial]    
    fn sap_bench_server_redeem() {
        create_dir_all("results/").unwrap();

        let mut comm_file = File::create("results/sap_redeem_computation.dat").unwrap();
        comm_file.write_all(b"# Redeem computation\n").unwrap();
        comm_file.write_all(b"# Batch/wallet size vs. CPU time (ms)\n").unwrap();

        let mut rng = OsRng;
        let signing_key = SigningKey::random(&mut rng);
        
        let mut client = Client {
            tokens: Arc::new(RwLock::new(Vec::new())),
            blinded_tokens: Arc::new(RwLock::new(Vec::new())),
            unblinded_tokens: Arc::new(RwLock::new(Vec::new())),
        };

        let mut server = Server {
            signing_key,
            //spent_tokens: Arc::new(RwLock::new(Vec::new())),
            bloom: Bloom::new_for_fp_rate(100000000, 0.000001),
        };

        const ITERS: u32 = 100;
        let mut durations = vec![];
        for hw in 1..13 {
            let mut duration = Duration::new(0, 0);
            for _ in 0..ITERS {
                let issue_request = client.issue_request(hw);
                let issue_response = server.issue(issue_request);
                client.issue_process(issue_response).unwrap();
                let win_notice = WinNotice { price: 42 };        
                let redeem_request = client.redeem_request(&win_notice);
                let start = Instant::now();
                let redeem_response = server.redeem(redeem_request);
                duration += start.elapsed();
                // Reset state
                assert!(redeem_response.valid);                                
                server.bloom.clear();
                client.reset_state();
            }
            let avg_duration = duration.checked_div(ITERS).unwrap().as_millis();
            durations.push(avg_duration);
        }
        
        for v in 1..=4096u32 {
            let hw = hamming::weight(&v.to_be_bytes());
            comm_file.write_all(format!("{} {}\n", v, durations[(hw-1) as usize]).as_bytes()).unwrap();
        }        
    }            
    
    //#[test]
    //fn e2e_voprf() {
    //    let mut rng = OsRng;
    //    let signing_key = SigningKey::random(&mut rng);
    //
    //    let mut advertiser = Advertiser {
    //        tokens: Arc::new(RwLock::new(Vec::new())),
    //        blinded_tokens: Arc::new(RwLock::new(Vec::new())),
    //        unblinded_tokens: Arc::new(RwLock::new(Vec::new())),
    //    };
    //    let mut exchange = Exchange {
    //        signing_key,
    //        spent_tokens: Arc::new(RwLock::new(Vec::new())),
    //    };
    //
    //    let start = Instant::now();        
    //    let signing_req = advertiser.create_tokens(128);
    //    println!("Advertiser create tokens: {:?}", start.elapsed());
    //
    //    let start = Instant::now();
    //    let signing_resp = exchange.sign_tokens(signing_req);
    //    println!("Exchange sign tokens: {:?}", start.elapsed());
    //    advertiser.store_signed_tokens(signing_resp).unwrap();
    //
    //    let win_notice = WinNotice { price: 42 };
    //    let redeem_request = advertiser.redeem_tokens(&win_notice);
    //    let start = Instant::now();                
    //    exchange.redeem_tokens(&redeem_request);
    //    println!("Exchange redeem tokens: {:?}", start.elapsed());        
    //}
}
