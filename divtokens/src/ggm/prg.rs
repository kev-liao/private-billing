// TODO: Clean up
pub struct PRG {
}

impl PRG {
    pub fn new() -> Self {
        Self { }
    }

    // TODO: Error handling
    pub fn eval(&self,
                key: &[u8; 32],
                out_blocks: &mut [[u8; 32]; 2]) {
        let mut hasher = blake3::Hasher::new();
        hasher.update(key);
        hasher.update(&[0]);
        out_blocks[0] = *hasher.finalize().as_bytes();
        let mut hasher = blake3::Hasher::new();
        hasher.update(key);
        hasher.update(&[1]);
        out_blocks[1] = *hasher.finalize().as_bytes();
    }

    // TODO: Error handling
    pub fn evalf(&self, bit: bool, key: &mut [u8; 32]) {
        //let cipher = Aes128::new(&key);
        if bit {
            let mut hasher = blake3::Hasher::new();
            hasher.update(key);
            hasher.update(&[1]);
            *key = *hasher.finalize().as_bytes();
        } else {
            let mut hasher = blake3::Hasher::new();
            hasher.update(key);
            hasher.update(&[0]);
            *key = *hasher.finalize().as_bytes();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use rand::Rng;    

    #[test]
    fn prg_test() {
        let key = rand::thread_rng().gen::<[u8; 32]>();
        let prg = PRG::new();
        
        let mut blocks = [[0u8; 32]; 2];
        prg.eval(&key, &mut blocks);

        println!("{:?}", blocks);
    }
    
    #[test]
    fn prg_consistency_test() {
        let key = rand::thread_rng().gen::<[u8; 32]>();
        let prg = PRG::new();
        
        let mut blocks1 = [[0u8; 32]; 2];
        prg.eval(&key, &mut blocks1);
    
        let mut blocks2 = [key.clone(), key.clone()];
        prg.evalf(false, &mut blocks2[0]);
        prg.evalf(true, &mut blocks2[1]);
    
        assert_eq!(blocks1, blocks2);
    }        
}
