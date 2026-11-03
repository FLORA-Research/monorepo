//! Aggregator flash storage: the config and identity records, two banks each.
//!
//! The record layouts live in `flora_drivers::config` and
//! `flora_device::identity`, so their encoding is host-tested; this module is
//! the part that cannot be: the RP2040 flash peripheral, the
//! erase-then-write-then-verify cycle, and the bank alternation that keeps a
//! power loss mid-write from losing the identity.
//!
//! The four banks are the last four erase sectors of flash, below the
//! firmware. Config and identity are separate pairs so saving a threshold
//! never touches the identity: that record is the one thing on the device
//! that cannot be recovered by re-flashing.

use embassy_rp::flash::{Blocking, ERASE_SIZE, Flash};
use embassy_rp::peripherals::FLASH;
use flora_device::identity::{
    Identity, StorageError, decode_identity, encode_identity, generation_is_newer,
};
use flora_drivers::{CONFIG_PAGE_SIZE, NodeConfig};

use crate::uplink::UplinkConfig;

pub const FLASH_SIZE: usize = 2 * 1024 * 1024;
const BANK_SIZE: usize = ERASE_SIZE;
const STORAGE_START: usize = FLASH_SIZE - 4 * BANK_SIZE;
const CONFIG_BANKS: [usize; 2] = [0, 1];
const IDENTITY_BANKS: [usize; 2] = [2, 3];

pub struct UplinkStorage<'d> {
    flash: Flash<'d, FLASH, Blocking, FLASH_SIZE>,
    config: NodeConfig,
    config_bank: Option<usize>,
    config_generation: u32,
    identity: Identity,
    identity_bank: Option<usize>,
    identity_generation: u32,
}

impl<'d> UplinkStorage<'d> {
    pub fn new(flash: Flash<'d, FLASH, Blocking, FLASH_SIZE>) -> Result<Self, StorageError> {
        let mut storage = Self {
            flash,
            config: NodeConfig::default(),
            config_bank: None,
            config_generation: 0,
            identity: Identity::EMPTY,
            identity_bank: None,
            identity_generation: 0,
        };
        storage.load_config()?;
        storage.load_identity()?;
        Ok(storage)
    }

    pub fn config(&self) -> NodeConfig {
        self.config
    }

    /// The flash chip's unique id: stable for the life of the board.
    ///
    /// The provisioning greeting derives the device's UUID and public key
    /// from it, so it must be readable before any identity exists.
    pub fn unique_id(&mut self) -> Result<[u8; 8], StorageError> {
        let mut uuid = [0u8; 8];
        self.flash
            .blocking_unique_id(&mut uuid)
            .map_err(|_| StorageError::Flash)?;
        if uuid == [0; 8] || uuid == [0xFF; 8] {
            return Err(StorageError::InvalidUniqueId);
        }
        Ok(uuid)
    }

    /// The aggregator's identity as the cloud knows it.
    pub fn identity(&self) -> &Identity {
        &self.identity
    }

    pub fn gateway_id(&self) -> [u8; flora_protocol::GATEWAY_ID_LEN] {
        self.identity.gateway_id
    }

    pub fn is_provisioned(&self) -> bool {
        self.identity.is_provisioned()
    }

    /// Everything the uplink needs, borrowed from the identity record.
    pub fn uplink_config(&self) -> UplinkConfig<'_> {
        UplinkConfig {
            base_url: self.identity.cloud_url(),
            device_id: self.identity.device_id(),
            device_token_hex: self.identity.device_token(),
        }
    }

    pub fn save_config(&mut self, config: NodeConfig) -> Result<(), StorageError> {
        if !config.validate() {
            return Err(StorageError::VerifyFailed);
        }
        if config == self.config {
            return Ok(());
        }
        let bank = next_bank(self.config_bank, &CONFIG_BANKS);
        let generation = self.config_generation.wrapping_add(1);
        let mut page = [0xFFu8; CONFIG_PAGE_SIZE];
        config.encode_record(generation, &mut page);
        self.write_and_verify(bank, &page)?;
        if NodeConfig::decode_record(&page) != Some((generation, config)) {
            return Err(StorageError::VerifyFailed);
        }
        self.config = config;
        self.config_bank = Some(bank);
        self.config_generation = generation;
        Ok(())
    }

    pub fn save_identity(&mut self, identity: Identity) -> Result<(), StorageError> {
        if !identity.is_provisioned() {
            return Err(StorageError::VerifyFailed);
        }
        if identity == self.identity {
            return Ok(());
        }
        let bank = next_bank(self.identity_bank, &IDENTITY_BANKS);
        let generation = self.identity_generation.wrapping_add(1);
        let mut page = [0xFFu8; flora_device::identity::RECORD_PAGE_SIZE];
        encode_identity(&identity, generation, &mut page);
        self.write_and_verify(bank, &page)?;
        if decode_identity(&page) != Some((generation, identity)) {
            return Err(StorageError::VerifyFailed);
        }
        self.identity = identity;
        self.identity_bank = Some(bank);
        self.identity_generation = generation;
        Ok(())
    }

    fn write_and_verify(&mut self, bank: usize, page: &[u8]) -> Result<(), StorageError> {
        let offset = bank_offset(bank) as u32;
        self.flash
            .blocking_erase(offset, offset + ERASE_SIZE as u32)
            .map_err(|_| StorageError::Flash)?;
        self.flash
            .blocking_write(offset, page)
            .map_err(|_| StorageError::Flash)?;

        // Read back before accepting: a write that silently dropped bytes
        // would otherwise be discovered only after the next reboot.
        let mut verify = [0xFFu8; flora_device::identity::RECORD_PAGE_SIZE];
        let end = page.len().min(verify.len());
        self.flash
            .blocking_read(offset, &mut verify[..end])
            .map_err(|_| StorageError::Flash)?;
        if verify[..end] != page[..end] {
            return Err(StorageError::VerifyFailed);
        }
        Ok(())
    }

    fn load_config(&mut self) -> Result<(), StorageError> {
        let mut pages = [[0xFFu8; CONFIG_PAGE_SIZE]; CONFIG_BANKS.len()];
        for (index, page) in pages.iter_mut().enumerate() {
            self.flash
                .blocking_read(bank_offset(CONFIG_BANKS[index]) as u32, page)
                .map_err(|_| StorageError::Flash)?;
        }
        let records = pages.map(|page| NodeConfig::decode_record(&page));
        if let Some((bank, (generation, config))) = newest(records, &CONFIG_BANKS) {
            self.config_bank = Some(bank);
            self.config_generation = generation;
            self.config = config;
        }
        Ok(())
    }

    fn load_identity(&mut self) -> Result<(), StorageError> {
        let mut pages = [[0xFFu8; flora_device::identity::RECORD_PAGE_SIZE]; IDENTITY_BANKS.len()];
        for (index, page) in pages.iter_mut().enumerate() {
            self.flash
                .blocking_read(bank_offset(IDENTITY_BANKS[index]) as u32, page)
                .map_err(|_| StorageError::Flash)?;
        }
        let records = pages.map(|page| decode_identity(&page));
        if let Some((bank, (generation, identity))) = newest(records, &IDENTITY_BANKS) {
            self.identity_bank = Some(bank);
            self.identity_generation = generation;
            self.identity = identity;
        }
        Ok(())
    }
}

/// Pick the bank the next write goes to: the other one, so the current
/// record survives until the replacement has been verified.
fn next_bank(current: Option<usize>, banks: &[usize; 2]) -> usize {
    match current {
        Some(bank) if bank == banks[0] => banks[1],
        _ => banks[0],
    }
}

/// Newest valid record, or `None` when both banks are blank.
fn newest<T: Copy>(
    records: [Option<(u32, T)>; 2],
    banks: &[usize; 2],
) -> Option<(usize, (u32, T))> {
    match (records[0], records[1]) {
        (Some(left), Some(right)) => {
            if generation_is_newer(left.0, right.0) {
                Some((banks[0], left))
            } else {
                Some((banks[1], right))
            }
        }
        (Some(left), None) => Some((banks[0], left)),
        (None, Some(right)) => Some((banks[1], right)),
        (None, None) => None,
    }
}

fn bank_offset(bank: usize) -> usize {
    STORAGE_START + bank * BANK_SIZE
}
