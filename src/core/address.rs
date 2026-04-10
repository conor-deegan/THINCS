/// ADRS (Address) structure per FIPS 205 §4.2.
///
/// A 32-byte value encoding position within the hypertree.
/// Fields are stored big-endian within the byte array.
///
/// Layout (byte offsets):
///   [0..3]   layer address
///   [4..15]  tree address (96 bits)
///   [16..19] type
///   [20..31] type-specific fields (depends on address type)

#[derive(Debug, Clone, Copy)]
pub struct Adrs {
    data: [u8; 32],
}

// Address types per FIPS 205
pub const WOTS_HASH: u32 = 0;
pub const WOTS_PK: u32 = 1;
pub const TREE: u32 = 2;
pub const FORS_TREE: u32 = 3;
pub const FORS_ROOTS: u32 = 4;
pub const WOTS_PRF: u32 = 5;
pub const FORS_PRF: u32 = 6;

impl Adrs {
    pub fn new() -> Self {
        Adrs { data: [0u8; 32] }
    }

    /// Get the raw 32-byte address (used by SHAKE variants).
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.data
    }

    /// Compressed 22-byte ADRS used by SHA-2 variants per FIPS 205 §11.2 /
    /// SPHINCS+ reference `sha2_offsets.h`.
    ///
    /// SHA-2 layout (reference):
    ///   byte  0     : layer address (1 byte)
    ///   bytes 1..9  : tree address (8 bytes, big-endian)
    ///   byte  9     : type (1 byte)
    ///   bytes 10..14: keypair address (4 bytes, big-endian)
    ///   byte  14    : — (unused in compression)
    ///   byte  17    : chain address or tree height (1 byte)
    ///   bytes 18..22: hash address or tree index (4 bytes, big-endian)
    ///
    /// Our internal ADRS uses the SHAKE layout (32 bytes), so we carve out
    /// the compressed form from:
    ///   - layer low byte     : data[3]
    ///   - tree addr low 8B   : data[8..16]
    ///   - type low byte      : data[19]
    ///   - type-specific 12B  : data[20..32]
    ///
    /// The `[14..17]` region in the compressed form lands on the upper three
    /// bytes of the SHAKE-layout `chain_address` (bytes [24..27]) and is
    /// expected to be zero. This holds whenever chain_address, tree_height,
    /// and hash_address all fit in a single byte — which the validator
    /// guarantees via `a <= 31` and `hp <= 32` and WOTS+ `len < 256`.
    pub fn as_compressed_bytes(&self) -> [u8; 22] {
        // In debug builds, assert that the bytes we'll silently drop are zero.
        // WOTS+: chain_address (u32 at 24..28) should be < 256
        //        hash_address (u32 at 28..32) should be < 256 (=> w-1 <= 255)
        //        tree_height shares bytes 24..28, always < 256
        debug_assert!(
            self.data[24] == 0 && self.data[25] == 0 && self.data[26] == 0,
            "upper 3 bytes of chain_address / tree_height must be zero for SHA-2 compression"
        );
        // Note: data[28..32] may be tree_index (up to 4 bytes) for FORS/TREE
        // types — that's fine, the full 4 bytes land in compressed[18..22].
        let mut out = [0u8; 22];
        out[0] = self.data[3];
        out[1..9].copy_from_slice(&self.data[8..16]);
        out[9] = self.data[19];
        out[10..22].copy_from_slice(&self.data[20..32]);
        out
    }

    /// Set layer address (bytes 0..4)
    pub fn set_layer_address(&mut self, layer: u32) {
        self.data[0..4].copy_from_slice(&layer.to_be_bytes());
    }

    pub fn get_layer_address(&self) -> u32 {
        u32::from_be_bytes(self.data[0..4].try_into().unwrap())
    }

    /// Set tree address (bytes 4..16, 96 bits)
    /// We use a u64 for the lower 64 bits (bytes 8..16), upper 32 bits (bytes 4..8) set to 0
    pub fn set_tree_address(&mut self, tree: u64) {
        self.data[4..8].copy_from_slice(&[0u8; 4]);
        self.data[8..16].copy_from_slice(&tree.to_be_bytes());
    }

    pub fn get_tree_address(&self) -> u64 {
        u64::from_be_bytes(self.data[8..16].try_into().unwrap())
    }

    /// Set address type (bytes 16..20)
    pub fn set_type(&mut self, addr_type: u32) {
        self.data[16..20].copy_from_slice(&addr_type.to_be_bytes());
        // Zero out the type-specific fields when changing type
        self.data[20..32].fill(0);
    }

    pub fn get_type(&self) -> u32 {
        u32::from_be_bytes(self.data[16..20].try_into().unwrap())
    }

    // === Type-specific field setters ===

    /// Set keypair address (bytes 20..24) — used by WOTS_HASH, WOTS_PK, WOTS_PRF, FORS_TREE, FORS_ROOTS, FORS_PRF
    pub fn set_keypair_address(&mut self, keypair: u32) {
        self.data[20..24].copy_from_slice(&keypair.to_be_bytes());
    }

    pub fn get_keypair_address(&self) -> u32 {
        u32::from_be_bytes(self.data[20..24].try_into().unwrap())
    }

    /// Set chain address (bytes 24..28) — used by WOTS_HASH, WOTS_PRF
    pub fn set_chain_address(&mut self, chain: u32) {
        self.data[24..28].copy_from_slice(&chain.to_be_bytes());
    }

    /// Set hash address (bytes 28..32) — used by WOTS_HASH, WOTS_PRF
    pub fn set_hash_address(&mut self, hash: u32) {
        self.data[28..32].copy_from_slice(&hash.to_be_bytes());
    }

    /// Set tree height (bytes 24..28) — used by TREE, FORS_TREE
    pub fn set_tree_height(&mut self, height: u32) {
        self.data[24..28].copy_from_slice(&height.to_be_bytes());
    }

    pub fn get_tree_height(&self) -> u32 {
        u32::from_be_bytes(self.data[24..28].try_into().unwrap())
    }

    /// Set tree index (bytes 28..32) — used by TREE, FORS_TREE
    pub fn set_tree_index(&mut self, index: u32) {
        self.data[28..32].copy_from_slice(&index.to_be_bytes());
    }

    pub fn get_tree_index(&self) -> u32 {
        u32::from_be_bytes(self.data[28..32].try_into().unwrap())
    }
}

impl Default for Adrs {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_adrs_layer_address() {
        let mut adrs = Adrs::new();
        adrs.set_layer_address(5);
        assert_eq!(adrs.get_layer_address(), 5);
    }

    #[test]
    fn test_adrs_tree_address() {
        let mut adrs = Adrs::new();
        adrs.set_tree_address(0x123456789ABCDEF0);
        assert_eq!(adrs.get_tree_address(), 0x123456789ABCDEF0);
    }

    #[test]
    fn test_adrs_type_clears_fields() {
        let mut adrs = Adrs::new();
        adrs.set_type(WOTS_HASH);
        adrs.set_keypair_address(42);
        adrs.set_chain_address(7);
        adrs.set_hash_address(3);
        // Changing type should zero out type-specific fields
        adrs.set_type(TREE);
        assert_eq!(adrs.get_keypair_address(), 0);
    }

    #[test]
    fn test_adrs_32_bytes() {
        let adrs = Adrs::new();
        assert_eq!(adrs.as_bytes().len(), 32);
    }

    #[test]
    fn test_adrs_compressed_layout_wots() {
        // WOTS+ use case: chain_address and hash_address must fit in one byte
        // (enforced by the parameter validator).
        let mut adrs = Adrs::new();
        adrs.set_layer_address(0x12);
        adrs.set_tree_address(0xAABBCCDDEEFF0011);
        adrs.set_type(WOTS_HASH);
        adrs.set_keypair_address(0x33445566);
        adrs.set_chain_address(0x0000005A);
        adrs.set_hash_address(0x0000003C);

        let c = adrs.as_compressed_bytes();
        assert_eq!(c.len(), 22);
        assert_eq!(c[0], 0x12);
        assert_eq!(&c[1..9], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]);
        assert_eq!(c[9], 0x00); // type = WOTS_HASH
        assert_eq!(&c[10..14], &[0x33, 0x44, 0x55, 0x66]); // keypair
        assert_eq!(&c[14..17], &[0x00, 0x00, 0x00]); // upper bytes of chain always 0
        assert_eq!(c[17], 0x5A); // low byte of chain_address (SPX_OFFSET_CHAIN_ADDR)
        assert_eq!(&c[18..21], &[0x00, 0x00, 0x00]); // upper bytes of hash always 0
        assert_eq!(c[21], 0x3C); // low byte of hash_address (SPX_OFFSET_HASH_ADDR)
    }

    #[test]
    fn test_adrs_compressed_layout_tree() {
        // TREE/FORS_TREE use case: tree_index uses all 4 bytes, tree_height
        // is still single-byte.
        let mut adrs = Adrs::new();
        adrs.set_layer_address(0x12);
        adrs.set_tree_address(0xAABBCCDDEEFF0011);
        adrs.set_type(TREE);
        adrs.set_tree_height(0x0000001F);
        adrs.set_tree_index(0xDEADBEEF);

        let c = adrs.as_compressed_bytes();
        assert_eq!(c[0], 0x12);
        assert_eq!(&c[1..9], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11]);
        assert_eq!(c[9], 0x02); // type = TREE
        assert_eq!(&c[10..14], &[0x00, 0x00, 0x00, 0x00]); // keypair zero for TREE
        assert_eq!(&c[14..17], &[0x00, 0x00, 0x00]);
        assert_eq!(c[17], 0x1F); // tree_height (SPX_OFFSET_TREE_HGT)
        assert_eq!(&c[18..22], &[0xDE, 0xAD, 0xBE, 0xEF]); // tree_index 4 bytes (SPX_OFFSET_TREE_INDEX)
    }
}
