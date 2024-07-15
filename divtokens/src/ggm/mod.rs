use bit_vec::BitVec;

use crate::ggm::prg::PRG;

pub mod prg;

pub struct GGM {
    pub prg: PRG,
}

impl GGM {
    pub fn new() -> Self {
        let prg = PRG::new();
        Self { prg }
    }

    pub fn eval(&self,
                key: &[u8; 32],
                x: &BitVec)
                -> [u8; 32] {
        let mut out = key.clone();
        for bit in x {
            self.prg.evalf(bit, &mut out);
        }
        return out;
    }
    
    pub fn expand(&self,
                  key: &[u8; 32],
                  depth: u8)
                  -> Vec<[u8; 32]> {
        match depth {
            0 => vec![*key],
            1 => {
                let mut blocks = [[0u8; 32]; 2];                
                self.prg.eval(&key, &mut blocks);
                blocks.to_vec()
            },
            n => {
                let mut blocks = [[0u8; 32]; 2];
                self.prg.eval(&key, &mut blocks);
                let mut l_tree = self.expand(&blocks[0], n - 1);
                let r_tree = self.expand(&blocks[1], n - 1);
                l_tree.extend(r_tree);
                l_tree
            },
        }
    }
}


pub fn u16_to_bv(x: u16, bv_len: usize) -> BitVec {
    let mut bv = BitVec::from_bytes(&x.to_be_bytes());
    bv.split_off(16 - bv_len)
}

#[cfg(test)]
mod test {
    use super::*;
    use bit_vec::BitVec;
    use rand::Rng;
    use std::time::Instant;

    use crate::ggm::prg::PRG;
    
    #[test]
    fn ggm_consistency_test() {
        let key = rand::thread_rng().gen::<[u8; 32]>();
        let input1 = BitVec::from_bytes(&rand::thread_rng().gen::<[u8; 1]>());
        let input2 = input1.clone();
        
        let mut out1 = key.clone();
        let prg = PRG::new();
        for bit in input1 {
            prg.evalf(bit, &mut out1);
        }

        let prf = GGM::new();
        let out2 = prf.eval(&key, &input2);
        
        assert_eq!(out1, out2);
    }

    #[test]
    fn ggm_expand_test() {
        let key = rand::thread_rng().gen::<[u8; 32]>();
        let ggm = GGM::new();

        // Check expand with depth 0
        let depth = 0;
        let out0 = ggm.expand(&key, depth);
        assert_eq!(out0, vec![key]);

        // Check expand with depth 1
        let depth = 1;
        let out1 = ggm.expand(&key, depth);
        for i in 0..u16::pow(2, depth.into()) {
            let x = u16_to_bv(i, depth.into());
            assert_eq!(out1[i as usize], ggm.eval(&key, &x));
        }

        // Check expand with depth 10
        let depth = 10;
        let start = Instant::now();
        let out10 = ggm.expand(&key, depth);
        println!("Expand 10: {:?}", start.elapsed());
        for i in 0..u16::pow(2, depth.into()) {
            let x = u16_to_bv(i, depth.into());
            assert_eq!(out10[i as usize], ggm.eval(&key, &x));
        }
    }
}
