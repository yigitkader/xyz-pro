//! Reader Adapter - Implements Bridge Traits
//!
//! This module provides the bridge between TargetSet and the
//! Matcher trait, allowing clean integration with the pipeline.

use std::sync::Arc;

use crate::bridge::{KeyBatch, Match, MatchType, Matcher, MatcherStats, RawKeyData};
use super::TargetSet;

/// Adapter that wraps TargetSet and implements Matcher trait
pub struct TargetMatcher {
    targets: Arc<TargetSet>,
}

impl TargetMatcher {
    /// Create a new matcher from a TargetSet
    pub fn new(targets: TargetSet) -> Self {
        Self {
            targets: Arc::new(targets),
        }
    }
    
    /// Create from Arc<TargetSet>
    pub fn from_arc(targets: Arc<TargetSet>) -> Self {
        Self { targets }
    }
    
    /// Load targets from file and create matcher
    pub fn load<P: AsRef<std::path::Path>>(path: P) -> Result<Self, String> {
        let targets = TargetSet::load(path)?;
        Ok(Self::new(targets))
    }
    
    /// Get inner TargetSet
    pub fn inner(&self) -> &TargetSet {
        &self.targets
    }
}

impl Matcher for TargetMatcher {
    fn check_batch(&self, batch: &KeyBatch) -> Vec<Match> {
        let mut matches = Vec::new();
        
        for key in batch.iter() {
            if !key.is_valid() {
                continue;
            }
            
            let match_types = self.check_key(&key.pubkey_hash, &key.p2sh_hash);
            
            for mt in match_types {
                matches.push(Match::new(key, mt));
            }
        }
        
        matches
    }
    
    fn check_key(&self, pubkey_hash: &[u8; 20], p2sh_hash: &[u8; 20]) -> Vec<MatchType> {
        let mut matches = Vec::new();
        
        // Check P2PKH (pubkey_hash is RIPEMD160(SHA256(compressed_pubkey)))
        if self.targets.contains_hash160(pubkey_hash) {
            matches.push(MatchType::P2PKH);
        }
        
        // Check P2SH (p2sh_hash is RIPEMD160(SHA256(witness_script)))
        if self.targets.contains_p2sh(p2sh_hash) {
            matches.push(MatchType::P2SH);
        }
        
        // Check P2WPKH (same hash160 as P2PKH, different address encoding)
        // Only add if not already matched as P2PKH to avoid duplicates
        if !matches.contains(&MatchType::P2PKH) && self.targets.contains_hash160(pubkey_hash) {
            matches.push(MatchType::P2WPKH);
        }
        
        matches
    }
    
    fn target_count(&self) -> usize {
        self.targets.stats.total
    }
    
    fn stats(&self) -> MatcherStats {
        MatcherStats {
            total: self.targets.stats.total,
            p2pkh: self.targets.stats.p2pkh,
            p2sh: self.targets.stats.p2sh,
            p2wpkh: self.targets.stats.p2wpkh,
        }
    }
}

/// Parallel matcher - uses rayon for batch processing
pub struct ParallelMatcher {
    inner: TargetMatcher,
}

impl ParallelMatcher {
    pub fn new(targets: TargetSet) -> Self {
        Self {
            inner: TargetMatcher::new(targets),
        }
    }
    
    pub fn load<P: AsRef<std::path::Path>>(path: P) -> Result<Self, String> {
        Ok(Self {
            inner: TargetMatcher::load(path)?,
        })
    }
}

impl Matcher for ParallelMatcher {
    fn check_batch(&self, batch: &KeyBatch) -> Vec<Match> {
        use rayon::prelude::*;
        
        let data = batch.as_bytes();
        
        data.par_chunks(RawKeyData::SIZE)
            .filter_map(|chunk| {
                let key = RawKeyData::from_bytes(chunk)?;
                if !key.is_valid() {
                    return None;
                }
                
                let match_types = self.check_key(&key.pubkey_hash, &key.p2sh_hash);
                if match_types.is_empty() {
                    return None;
                }
                
                // Return first match type (could return all if needed)
                Some(Match::new(key, match_types[0]))
            })
            .collect()
    }
    
    fn check_key(&self, pubkey_hash: &[u8; 20], p2sh_hash: &[u8; 20]) -> Vec<MatchType> {
        self.inner.check_key(pubkey_hash, p2sh_hash)
    }
    
    fn target_count(&self) -> usize {
        self.inner.target_count()
    }
    
    fn stats(&self) -> MatcherStats {
        self.inner.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_matcher_stats() {
        // Would need actual test data
    }
}

