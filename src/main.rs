use anyhow::{anyhow, bail, Result};
use rayon::iter::{IntoParallelIterator, ParallelIterator};
use scroll::{Pread, LE};

use crate::rgp::{RgpAsicInfo, RgpEntryHeader, RgpHeader, SqttFileChunkType, ENTRY_HEADER_SIZE};
use crate::sqtt::{parse_sqtt, SqttChunk, SqttChunkAnalysis};

mod merge;
mod rgp;
mod sqtt;
mod userdata;

struct ParsedTrace {
    asic_info: RgpAsicInfo,
    chunks: Vec<SqttChunk>,
}

impl ParsedTrace {
    fn new(data: &[u8]) -> Result<ParsedTrace> {
        use SqttFileChunkType::*;
        let hdr: RgpHeader = data.pread_with(0, LE)?;
        let mut asic_info = None;
        let mut offset = hdr.chunk_offset as usize;
        let mut sqtt_chunks = vec![];
        while offset < data.len() {
            let entry: RgpEntryHeader = data.pread_with(offset, LE)?;
            if entry.size < ENTRY_HEADER_SIZE as _ {
                bail!("Corrupt chunk (size too small)");
            }
            let len = (entry.size as usize) - ENTRY_HEADER_SIZE;
            let chunk_type: SqttFileChunkType = entry.chunk_id.ty.try_into()?;
            match chunk_type {
                AsicInfo => {
                    let start = offset + ENTRY_HEADER_SIZE;
                    asic_info = Some(data.pread_with(start, LE)?);
                }
                SqttData => {
                    let start = offset + ENTRY_HEADER_SIZE + 8;
                    let sqtt_data = &data[start..offset + len];
                    sqtt_chunks.push(sqtt_data);
                }
                _ => {}
            }
            offset += entry.size as usize;
        }
        let asic_info = asic_info.ok_or_else(|| anyhow!("No asic info found"))?;
        let chunks = sqtt_chunks
            .into_par_iter()
            .map(|chunk| -> Result<_> {
                let chunk = parse_sqtt(chunk, &asic_info)?;
                let analysis = SqttChunkAnalysis::new(&chunk, &asic_info);
                Ok(chunk)
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(ParsedTrace { asic_info, chunks })
    }
}


fn main() {
    let file = std::env::args().nth(1).expect("No file given");
    let _trace = ParsedTrace::new(&std::fs::read(file).unwrap()).unwrap();
}
