//! Node flash storage: the config record's two-bank rotation.
//!
//! The record layout lives in `flora_drivers::config`, so the encoding is
//! host-tested; this module is the part that cannot be: the RP2040 flash
//! peripheral, the erase-then-write-then-verify cycle, and the bank
//! alternation that keeps a power loss mid-write from bricking the config.

use embassy_rp::flash::{Blocking, ERASE_SIZE, Flash};
use embassy_rp::peripherals::FLASH;

use flora_device::identity::{StorageError, generation_is_newer};
use flora_drivers::{CONFIG_PAGE_SIZE, NodeConfig};

pub const FLASH_SIZE: usize = 2 * 1024 * 1024;
const CONFIG_BANKS: usize = 2;
const BANK_SIZE: usize = ERASE_SIZE;
const CONFIG_START: usize = FLASH_SIZE - CONFIG_BANKS * BANK_SIZE;

pub struct NodeStorage<'d> {
    flash: Flash<'d, FLASH, Blocking, FLASH_SIZE>,
    config: NodeConfig,
    active_bank: Option<usize>,
    generation: u32,
}

impl<'d> NodeStorage<'d> {
    pub fn new(flash: Flash<'d, FLASH, Blocking, FLASH_SIZE>) -> Result<Self, StorageError> {
        let mut storage = Self {
            flash,
            config: NodeConfig::default(),
            active_bank: None,
            generation: 0,
        };
        storage.load_config()?;
        Ok(storage)
    }

    pub fn config(&self) -> NodeConfig {
        self.config
    }

    /// The flash chip's unique id, used as the node's bus UUID.
    ///
    /// It is stable for the life of the board and cannot be re-flashed,
    /// which is exactly what an identity needs: two nodes whose UUIDs
    /// collide would overwrite each other's readings.
    pub fn node_uuid(&mut self) -> Result<[u8; 8], StorageError> {
        let jedec = self
            .flash
            .blocking_jedec_id()
            .map_err(|_| StorageError::Flash)?;
        if (jedec >> 16) as u8 != 0xEF {
            return Err(StorageError::UnsupportedFlash);
        }
        let mut uuid = [0u8; 8];
        self.flash
            .blocking_unique_id(&mut uuid)
            .map_err(|_| StorageError::Flash)?;
        if uuid == [0; 8] || uuid == [0xFF; 8] {
            return Err(StorageError::InvalidUniqueId);
        }
        Ok(uuid)
    }

    pub fn save_config(&mut self, config: NodeConfig) -> Result<(), StorageError> {
        if !config.validate() {
            return Err(StorageError::VerifyFailed);
        }
        if config == self.config {
            return Ok(());
        }

        let target_bank = match self.active_bank {
            Some(0) => 1,
            Some(_) => 0,
            None => 0,
        };
        let generation = self.generation.wrapping_add(1);
        let offset = bank_offset(target_bank) as u32;
        self.flash
            .blocking_erase(offset, offset + ERASE_SIZE as u32)
            .map_err(|_| StorageError::Flash)?;

        let mut page = [0xFFu8; CONFIG_PAGE_SIZE];
        config.encode_record(generation, &mut page);
        self.flash
            .blocking_write(offset, &page)
            .map_err(|_| StorageError::Flash)?;

        // Read back before accepting: a write that silently dropped bytes
        // would otherwise be discovered only after the next reboot.
        let mut verify = [0xFFu8; CONFIG_PAGE_SIZE];
        self.flash
            .blocking_read(offset, &mut verify)
            .map_err(|_| StorageError::Flash)?;
        if NodeConfig::decode_record(&verify) != Some((generation, config)) {
            return Err(StorageError::VerifyFailed);
        }

        self.config = config;
        self.active_bank = Some(target_bank);
        self.generation = generation;
        Ok(())
    }

    fn load_config(&mut self) -> Result<(), StorageError> {
        let mut pages = [[0xFFu8; CONFIG_PAGE_SIZE]; CONFIG_BANKS];
        for (bank, page) in pages.iter_mut().enumerate() {
            self.flash
                .blocking_read(bank_offset(bank) as u32, page)
                .map_err(|_| StorageError::Flash)?;
        }
        let records = pages.map(|page| NodeConfig::decode_record(&page));
        let selected = match (records[0], records[1]) {
            (Some(left), Some(right)) => {
                if generation_is_newer(left.0, right.0) {
                    Some((0, left))
                } else {
                    Some((1, right))
                }
            }
            (Some(left), None) => Some((0, left)),
            (None, Some(right)) => Some((1, right)),
            (None, None) => None,
        };
        if let Some((bank, (generation, config))) = selected {
            self.active_bank = Some(bank);
            self.generation = generation;
            self.config = config;
        }
        Ok(())
    }
}

fn bank_offset(bank: usize) -> usize {
    CONFIG_START + bank * BANK_SIZE
}
