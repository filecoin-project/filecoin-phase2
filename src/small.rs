use std::fmt::{self, Debug, Formatter};
use std::fs::File;
use std::io::{self, BufReader, BufWriter, Read, Seek, SeekFrom, Write};

use blstrs::{Fp, G1Affine, G1Projective, G2Affine, Scalar as Fr};
use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use ff::Field;
use group::{prime::PrimeCurveAffine, Curve, Group};
use log::{error, info, warn};
use rand::RngCore;

use crate::{
    batch_exp, error_not_in_subgroup, error_not_on_curve, error_point_at_inf, hash_to_g2,
    merge_pairs, read_g1, read_g2, same_ratio, ts1::hash_to_g2_ts1, HashWriter, PrivateKey,
    PublicKey,
};

#[derive(Clone, PartialEq)]
pub struct MPCSmall {
    // The Groth16 verification-key's deltas G1 and G2. For all non-initial parameters
    // `delta_g1 == contributions.last().delta_after`.
    pub(crate) delta_g1: G1Affine,
    pub(crate) delta_g2: G2Affine,

    // The Groth16 parameter's h and l vectors.
    pub(crate) h: Vec<G1Affine>,
    pub(crate) l: Vec<G1Affine>,

    // The MPC parameter's constraint system digest and participant public-key set.
    pub(crate) cs_hash: [u8; 64],
    pub(crate) contributions: Vec<PublicKey>,
}

pub struct Streamer {
    delta_g1: G1Affine,
    delta_g2: G2Affine,
    h_len_offset: u64,
    cs_hash: [u8; 64],
    contributions: Vec<PublicKey>,
    path: String,
    read_raw: bool,
    write_raw: bool,
    check_subgroup: bool,
}

impl Streamer {
    // Create a new `Streamer` from small params file.
    pub fn new(
        path: &str,
        read_raw: bool,
        write_raw: bool,
        check_subgroup: bool,
    ) -> io::Result<Self> {
        let mut file = File::open(path)?;

        // Never use raw format.
        let delta_g1: G1Affine = read_g1(&mut file, check_subgroup)?;
        let delta_g2: G2Affine = read_g2(&mut file, check_subgroup)?;

        // Non-raw sizes.
        let g1_size = G1Affine::uncompressed_size(); // 96
        let g2_size = G2Affine::uncompressed_size(); // 192

        // Read large vectors using either raw or non-raw format.
        let chunk_element_read_size = if read_raw {
            G1Affine::raw_fmt_size()
        } else {
            g1_size
        };

        let h_len_offset = g1_size + g2_size;
        let h_len = file.read_u32::<BigEndian>()? as usize;
        file.seek(SeekFrom::Current((h_len * chunk_element_read_size) as i64))?;

        let l_len = file.read_u32::<BigEndian>()? as usize;
        file.seek(SeekFrom::Current((l_len * chunk_element_read_size) as i64))?;
        let mut cs_hash = [0u8; 64];
        file.read_exact(&mut cs_hash)?;

        let contributions_len = file.read_u32::<BigEndian>()? as usize;
        let mut contributions = Vec::<PublicKey>::with_capacity(contributions_len);
        for _ in 0..contributions_len {
            contributions.push(PublicKey::read(&mut file, check_subgroup)?);
        }

        let streamer = Streamer {
            delta_g1,
            delta_g2,
            h_len_offset: h_len_offset as u64,
            cs_hash,
            contributions,
            path: path.to_string(),
            read_raw,
            write_raw,
            check_subgroup,
        };

        Ok(streamer)
    }

    // Create a new `Streamer` from large params file.
    pub fn new_from_large_file(
        path: &str,
        read_raw: bool,
        write_raw: bool,
        check_subgroup: bool,
    ) -> io::Result<Self> {
        let mut file = File::open(path)?;

        /*
           `MPCParameters` are serialized in the order:
              vk.alpha_g1
              vk.beta_g1
              vk.beta_g2
              vk.gamma_g2
              vk.delta_g1
              vk.delta_g2
              vk.ic length (4 bytes)
              vk.ic (G1)
              h length (4 bytes)
              h (G1)
              l length (4 bytes)
              l (G1)
              a length (4 bytes)
              a (G1)
              b_g1 length (4 bytes)
              b_g1 (G1)
              b_g2 length (4 bytes)
              b_g2 (G2)
              cs_hash (64 bytes)
              contributions length (4 bytes)
              contributions (544 bytes per PublicKey)
        */

        // Non-raw sizes.
        let g1_size = G1Affine::uncompressed_size() as u64; // 96 bytes
        let g2_size = G2Affine::uncompressed_size() as u64; // 192 bytes

        // Read large vectors using either raw or non-raw format.
        let chunk_element_read_size = if read_raw {
            G1Affine::raw_fmt_size() as u64
        } else {
            g1_size
        };

        // Read delta_g1, delta_g2, and ic's length.
        let delta_g1_offset = g1_size + g1_size + g2_size + g2_size; // vk.alpha_g1 + vk.beta_g1 + vk.beta_g2 + vk.gamma_g2
        file.seek(SeekFrom::Start(delta_g1_offset)).unwrap();
        let delta_g1 = read_g1(&mut file, check_subgroup)?;
        let delta_g2 = read_g2(&mut file, check_subgroup)?;
        let ic_len = file.read_u32::<BigEndian>()? as u64;

        // Read h's length.
        let h_len_offset = delta_g1_offset + g1_size + g2_size + 4 + ic_len * g1_size; // + vk.delta_g1 + vk.delta_g2 + ic length + ic
        file.seek(SeekFrom::Start(h_len_offset)).unwrap();
        let h_len = file.read_u32::<BigEndian>()? as u64;

        // Read l's length.
        let l_len_offset = h_len_offset + 4 + h_len * chunk_element_read_size; // + h length + h
        file.seek(SeekFrom::Start(l_len_offset)).unwrap();
        let l_len = file.read_u32::<BigEndian>()? as u64;

        // Read a's length.
        let a_len_offset = l_len_offset + 4 + l_len * chunk_element_read_size; // + l length + l
        file.seek(SeekFrom::Start(a_len_offset)).unwrap();
        let a_len = file.read_u32::<BigEndian>()? as u64;

        // Read b_g1's length.
        let b_g1_len_offset = a_len_offset + 4 + a_len * g1_size; // + a length + a
        file.seek(SeekFrom::Start(b_g1_len_offset)).unwrap();
        let b_g1_len = file.read_u32::<BigEndian>()? as u64;

        // Read b_g2's length.
        let b_g2_len_offset = b_g1_len_offset + 4 + b_g1_len * g1_size; // + b_g1 length + b_g1
        file.seek(SeekFrom::Start(b_g2_len_offset)).unwrap();
        let b_g2_len = file.read_u32::<BigEndian>()? as u64;

        // Read cs_hash.
        let cs_hash_offset = b_g2_len_offset + 4 + b_g2_len * g2_size; // + b_g2 length + b_g2
        file.seek(SeekFrom::Start(cs_hash_offset)).unwrap();
        let mut cs_hash = [0u8; 64];
        file.read_exact(&mut cs_hash)?;

        // Read contribution's length.
        let contributions_len = file.read_u32::<BigEndian>()? as u64;

        // Read the contributions.
        let contributions_offset = cs_hash_offset + 64 + 4; // + 64-byte cs_hash + contributions length
        file.seek(SeekFrom::Start(contributions_offset)).unwrap();
        let mut contributions = Vec::<PublicKey>::with_capacity(contributions_len as usize);
        for _ in 0..contributions_len {
            contributions.push(PublicKey::read(&mut file, check_subgroup)?);
        }

        let streamer = Streamer {
            delta_g1,
            delta_g2,
            h_len_offset,
            cs_hash,
            contributions,
            path: path.to_string(),
            read_raw,
            write_raw,
            check_subgroup,
        };

        Ok(streamer)
    }

    pub fn contribute(
        &mut self,
        rng: impl RngCore,
        out_file: File,
        chunk_size: usize,
    ) -> io::Result<[u8; 64]> {
        let chunk_element_read_size = if self.read_raw {
            G1Affine::raw_fmt_size()
        } else {
            G1Affine::uncompressed_size()
        };
        let chunk_element_write_size = if self.write_raw {
            G1Affine::raw_fmt_size()
        } else {
            G1Affine::uncompressed_size()
        };

        let read_g1_using_fmt = if self.read_raw { read_g1_raw } else { read_g1 };

        let write_g1_using_fmt = if self.write_raw {
            write_g1_raw
        } else {
            write_g1
        };

        // TODO: this chunk size doesn't really make sense because raw format params also contain
        // non-raw points as well as `u32`s.
        let read_buf_size = chunk_element_read_size * chunk_size;
        let write_buf_size = chunk_element_write_size * chunk_size;

        let file = File::open(&self.path)?;
        let mut reader = BufReader::with_capacity(read_buf_size, file);
        let mut writer = BufWriter::with_capacity(write_buf_size, out_file);

        // TODO: make this compatible with ts1
        // let (pubkey, privkey) = keypair_ts1(rng, &self.cs_hash, &self.contributions, &self.delta_g1);
        let (pubkey, privkey) = keypair(rng, &self.cs_hash, &self.contributions, &self.delta_g1);

        self.delta_g1 = (self.delta_g1 * privkey.delta).to_affine();
        self.delta_g2 = (self.delta_g2 * privkey.delta).to_affine();

        let delta_inv = match privkey.delta.invert() {
            opt if opt.is_some().into() => opt.unwrap(),
            _ => panic!("private-key's `delta` is zero, cannot invert"),
        };

        writer.write_all(&self.delta_g1.to_uncompressed())?;
        writer.write_all(&self.delta_g2.to_uncompressed())?;

        {
            reader.seek(SeekFrom::Start(self.h_len_offset))?;
            let h_len = reader.read_u32::<BigEndian>()?;
            writer.write_u32::<BigEndian>(h_len)?;

            let chunks_to_read = h_len as usize;
            let mut chunks_read = 0;
            let mut this_chunk_size = usize::min(chunk_size, chunks_to_read);

            let mut h_chunk = Vec::<G1Affine>::with_capacity(this_chunk_size);

            info!("phase2::MPCParameters::contribute() beginning streaming h");
            while this_chunk_size > 0 {
                for _ in 0..this_chunk_size {
                    h_chunk.push(read_g1_using_fmt(&mut reader, self.check_subgroup)?);
                }
                chunks_read += this_chunk_size;

                batch_exp(&mut h_chunk, delta_inv);

                for h in &h_chunk {
                    write_g1_using_fmt(&mut writer, h)?;
                }

                this_chunk_size = usize::min(chunk_size, chunks_to_read - chunks_read);
                h_chunk.truncate(0);
            }
            info!("phase2::MPCParameters::contribute() finished streaming h");
        }
        {
            let l_len = reader.read_u32::<BigEndian>()?;
            writer.write_u32::<BigEndian>(l_len)?;

            let chunks_to_read = l_len as usize;
            let mut chunks_read = 0;
            let mut this_chunk_size = usize::min(chunk_size, chunks_to_read);

            let mut l_chunk = Vec::<G1Affine>::with_capacity(this_chunk_size);
            info!("phase2::MPCParameters::contribute() beginning streaming l");
            while this_chunk_size > 0 {
                for _ in 0..this_chunk_size {
                    l_chunk.push(read_g1_using_fmt(&mut reader, self.check_subgroup)?);
                }
                chunks_read += this_chunk_size;

                batch_exp(&mut l_chunk, delta_inv);

                for l in &l_chunk {
                    write_g1_using_fmt(&mut writer, l)?;
                }

                this_chunk_size = usize::min(chunk_size, chunks_to_read - chunks_read);
                l_chunk.truncate(0);
            }
            info!("phase2::MPCParameters::contribute() finished streaming l");
        }

        self.contributions.push(pubkey.clone());

        writer.write_all(&self.cs_hash)?;

        writer.write_u32::<BigEndian>(self.contributions.len() as u32)?;

        for pubkey in &self.contributions {
            pubkey.write(&mut writer)?;
        }

        {
            let sink = io::sink();
            let mut sink = HashWriter::new(sink);
            pubkey.write(&mut sink).unwrap();
            Ok(sink.into_hash())
        }
    }

    /// Read from self and write out to `writer`, respecting own `read_raw` and `write_raw` flags but without otherwise changing data.
    /// Useful for converting to and from raw format.
    pub fn transform_fmt(&mut self, out_file: File, chunk_size: usize) -> io::Result<()> {
        let chunk_element_read_size = if self.read_raw {
            G1Affine::raw_fmt_size()
        } else {
            G1Affine::uncompressed_size()
        };
        let chunk_element_write_size = if self.write_raw {
            G1Affine::raw_fmt_size()
        } else {
            G1Affine::uncompressed_size()
        };

        let read_g1_using_fmt = if self.read_raw { read_g1_raw } else { read_g1 };
        let write_g1_using_fmt = if self.write_raw {
            write_g1_raw
        } else {
            write_g1
        };

        // TODO: this chunk size doesn't really make sense because raw format params also contain
        // non-raw points as well as `u32`s.
        let read_buf_size = chunk_element_read_size * chunk_size;
        let write_buf_size = chunk_element_write_size * chunk_size;

        let file = File::open(&self.path)?;
        let mut reader = BufReader::with_capacity(read_buf_size, file);
        let mut writer = BufWriter::with_capacity(write_buf_size, out_file);

        writer.write_all(&self.delta_g1.to_uncompressed())?;
        writer.write_all(&self.delta_g2.to_uncompressed())?;

        reader.seek(SeekFrom::Start(self.h_len_offset))?;
        {
            let h_len = reader.read_u32::<BigEndian>()?;
            writer.write_u32::<BigEndian>(h_len)?;

            let chunks_to_read = h_len as usize;
            let mut chunks_read = 0;
            let mut this_chunk_size = usize::min(chunk_size, chunks_to_read);

            let mut h_chunk = Vec::<G1Affine>::with_capacity(this_chunk_size);

            info!("phase2::MPCParameters::convert() beginning streaming h");
            while this_chunk_size > 0 {
                for _ in 0..this_chunk_size {
                    h_chunk.push(read_g1_using_fmt(&mut reader, self.check_subgroup)?);
                }
                chunks_read += this_chunk_size;

                for h in &h_chunk {
                    write_g1_using_fmt(&mut writer, h)?;
                }

                this_chunk_size = usize::min(chunk_size, chunks_to_read - chunks_read);
                h_chunk.truncate(0);
            }
            info!("phase2::MPCParameters::convert() finished streaming h");
        }

        {
            let l_len = reader.read_u32::<BigEndian>()?;
            writer.write_u32::<BigEndian>(l_len)?;

            let chunks_to_read = l_len as usize;
            let mut chunks_read = 0;
            let mut this_chunk_size = usize::min(chunk_size, chunks_to_read - chunks_read);

            let mut l_chunk = Vec::<G1Affine>::with_capacity(this_chunk_size);
            info!("phase2::MPCParameters::convert() beginning streaming l");
            while this_chunk_size > 0 {
                for _ in 0..this_chunk_size {
                    l_chunk.push(read_g1_using_fmt(&mut reader, self.check_subgroup)?);
                }
                chunks_read += this_chunk_size;

                for l in &l_chunk {
                    write_g1_using_fmt(&mut writer, l)?;
                }

                this_chunk_size = usize::min(chunk_size, chunks_to_read - chunks_read);
                l_chunk.truncate(0);
            }
            info!("phase2::MPCParameters::convert() finished streaming l");
        }

        writer.write_all(&self.cs_hash)?;

        writer.write_u32::<BigEndian>(self.contributions.len() as u32)?;

        for pubkey in &self.contributions {
            pubkey.write(&mut writer)?;
        }
        Ok(())
    }

    pub fn cs_hash(&self) -> &[u8; 64] {
        &self.cs_hash
    }
}

// Required by `assert_eq!()`. Implement manually because `h` and `l` vectors can be big.
impl Debug for MPCSmall {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("MPCSmall")
            .field("delta_g1", &self.delta_g1)
            .field("delta_g2", &self.delta_g2)
            .field("h", &format!("Vec<G1Affine; len={}>", self.h.len()))
            .field("l", &format!("Vec<G1Affine; len={}>", self.l.len()))
            .field("cs_hash", &self.cs_hash)
            .field(
                "contributions",
                &format!("Vec<phase2::PublicKey; len={}>", self.contributions.len()),
            )
            .finish()
    }
}

impl MPCSmall {
    // TODO: make this compatible with ts1
    // pub fn contribute_ts1(&mut self, rng: impl rand_ts1::RngCore) -> [u8; 64] {
    pub fn contribute(&mut self, rng: impl RngCore) -> [u8; 64] {
        // TODO: make this compatible with ts1
        // let (pubkey, privkey) = keypair_ts1(rng, &self.cs_hash, &self.contributions, &self.delta_g1);
        let (pubkey, privkey) = keypair(rng, &self.cs_hash, &self.contributions, &self.delta_g1);

        self.delta_g1 = (self.delta_g1 * privkey.delta).to_affine();
        self.delta_g2 = (self.delta_g2 * privkey.delta).to_affine();

        let delta_inv = match privkey.delta.invert() {
            opt if opt.is_some().into() => opt.unwrap(),
            _ => panic!("private-key's `delta` is zero, cannot invert"),
        };

        info!("phase2::MPCParameters::contribute() batch_exp of h");
        batch_exp(&mut self.h, delta_inv);
        info!("phase2::MPCParameters::contribute() finished batch_exp of h");

        info!("phase2::MPCParameters::contribute() batch_exp of l");
        batch_exp(&mut self.l, delta_inv);
        info!("phase2::MPCParameters::contribute() finished batch_exp of l");

        self.contributions.push(pubkey.clone());

        {
            let sink = io::sink();
            let mut sink = HashWriter::new(sink);
            pubkey.write(&mut sink).unwrap();
            sink.into_hash()
        }
    }

    /// Deserialize these parameters.
    pub fn read<R: Read>(mut reader: R, raw: bool, check_subgroup: bool) -> io::Result<Self> {
        let read_g1_using_fmt = if raw { read_g1_raw } else { read_g1 };

        let delta_g1: G1Affine = read_g1(&mut reader, check_subgroup)?;
        let delta_g2: G2Affine = read_g2(&mut reader, check_subgroup)?;

        let h_len = reader.read_u32::<BigEndian>()? as usize;
        let mut h = Vec::<G1Affine>::with_capacity(h_len);
        for _ in 0..h_len {
            h.push(read_g1_using_fmt(&mut reader, check_subgroup)?);
        }

        let l_len = reader.read_u32::<BigEndian>()? as usize;
        let mut l = Vec::<G1Affine>::with_capacity(l_len);
        for _ in 0..l_len {
            l.push(read_g1_using_fmt(&mut reader, check_subgroup)?);
        }

        let mut cs_hash = [0u8; 64];
        reader.read_exact(&mut cs_hash)?;

        let contributions_len = reader.read_u32::<BigEndian>()? as usize;
        let mut contributions = Vec::<PublicKey>::with_capacity(contributions_len);
        for _ in 0..contributions_len {
            contributions.push(PublicKey::read(&mut reader, check_subgroup)?);
        }

        info!(
            "phase2::MPCSmall::read() read vector lengths: h={}, l={}, contributions={}",
            h.len(),
            l.len(),
            contributions.len(),
        );

        Ok(MPCSmall {
            delta_g1,
            delta_g2,
            h,
            l,
            cs_hash,
            contributions,
        })
    }

    pub fn read_from_large_file(large_path: &str, check_subgroup: bool) -> io::Result<Self> {
        /*
           `MPCParameters` are serialized in the order:
              vk.alpha_g1
              vk.beta_g1
              vk.beta_g2
              vk.gamma_g2
              vk.delta_g1
              vk.delta_g2
              vk.ic length (4 bytes)
              vk.ic (G1)
              h length (4 bytes)
              h (G1)
              l length (4 bytes)
              l (G1)
              a length (4 bytes)
              a (G1)
              b_g1 length (4 bytes)
              b_g1 (G1)
              b_g2 length (4 bytes)
              b_g2 (G2)
              cs_hash (64 bytes)
              contributions length (4 bytes)
              contributions (544 bytes per PublicKey)
        */

        // Non-raw sizes.
        let g1_size = G1Affine::uncompressed_size() as u64; // 96 bytes
        let g2_size = G2Affine::uncompressed_size() as u64; // 192 bytes

        let mut file = File::open(large_path)?;

        // Read delta_g1, delta_g2, and ic's length.
        let delta_g1_offset = g1_size + g1_size + g2_size + g2_size; // vk.alpha_g1 + vk.beta_g1 + vk.beta_g2 + vk.gamma_g2
        file.seek(SeekFrom::Start(delta_g1_offset)).unwrap();
        let delta_g1 = read_g1(&mut file, check_subgroup)?;
        let delta_g2 = read_g2(&mut file, check_subgroup)?;
        let ic_len = file.read_u32::<BigEndian>()? as u64;

        // Read h's length.
        let h_len_offset = delta_g1_offset + g1_size + g2_size + 4 + ic_len * g1_size; // + vk.delta_g1 + vk.delta_g2 + ic length + ic
        file.seek(SeekFrom::Start(h_len_offset)).unwrap();
        let h_len = file.read_u32::<BigEndian>()? as u64;

        // Read l's length.
        let l_len_offset = h_len_offset + 4 + h_len * g1_size; // + h length + h
        file.seek(SeekFrom::Start(l_len_offset)).unwrap();
        let l_len = file.read_u32::<BigEndian>()? as u64;

        // Read a's length.
        let a_len_offset = l_len_offset + 4 + l_len * g1_size; // + l length + l
        file.seek(SeekFrom::Start(a_len_offset)).unwrap();
        let a_len = file.read_u32::<BigEndian>()? as u64;

        // Read b_g1's length.
        let b_g1_len_offset = a_len_offset + 4 + a_len * g1_size; // + a length + a
        file.seek(SeekFrom::Start(b_g1_len_offset)).unwrap();
        let b_g1_len = file.read_u32::<BigEndian>()? as u64;

        // Read b_g2's length.
        let b_g2_len_offset = b_g1_len_offset + 4 + b_g1_len * g1_size; // + b_g1 length + b_g1
        file.seek(SeekFrom::Start(b_g2_len_offset)).unwrap();
        let b_g2_len = file.read_u32::<BigEndian>()? as u64;

        // Read cs_hash.
        let cs_hash_offset = b_g2_len_offset + 4 + b_g2_len * g2_size; // + b_g2 length + b_g2
        file.seek(SeekFrom::Start(cs_hash_offset)).unwrap();
        let mut cs_hash = [0u8; 64];
        file.read_exact(&mut cs_hash)?;

        // Read contribution's length.
        let contributions_len = file.read_u32::<BigEndian>()? as u64;

        // Reset seek position.
        drop(file);

        // Read the (potentially large) h, l, and contributions arrays using buffered io.
        let file = File::open(large_path)?;
        let mut reader = BufReader::with_capacity(1024 * 1024, file);

        // Read h.
        let h_offset = h_len_offset + 4; // + h length
        reader.seek(SeekFrom::Start(h_offset)).unwrap();
        let mut h = Vec::<G1Affine>::with_capacity(h_len as usize);
        for _ in 0..h_len {
            h.push(read_g1(&mut reader, check_subgroup)?);
        }

        // Read l. Skip l's length because it was already read.
        let _ = reader.read_u32::<BigEndian>()? as u64;
        let mut l = Vec::<G1Affine>::with_capacity(l_len as usize);
        for _ in 0..l_len {
            l.push(read_g1(&mut reader, check_subgroup)?);
        }

        // Read the contributions.
        let contributions_offset = cs_hash_offset + 64 + 4; // + 64-byte cs_hash + contributions length
        reader.seek(SeekFrom::Start(contributions_offset)).unwrap();
        let mut contributions = Vec::<PublicKey>::with_capacity(contributions_len as usize);
        for _ in 0..contributions_len {
            contributions.push(PublicKey::read(&mut reader, check_subgroup)?);
        }

        Ok(MPCSmall {
            delta_g1,
            delta_g2,
            h,
            l,
            cs_hash,
            contributions,
        })
    }

    // TODO: allow using raw format.
    pub fn write<W: Write>(&self, mut writer: W) -> io::Result<()> {
        writer.write_all(&self.delta_g1.to_uncompressed())?;
        writer.write_all(&self.delta_g2.to_uncompressed())?;

        writer.write_u32::<BigEndian>(self.h.len() as u32)?;
        for h in &*self.h {
            writer.write_all(&h.to_uncompressed())?;
        }

        writer.write_u32::<BigEndian>(self.l.len() as u32)?;
        for l in &*self.l {
            writer.write_all(&l.to_uncompressed())?;
        }

        writer.write_all(&self.cs_hash)?;

        writer.write_u32::<BigEndian>(self.contributions.len() as u32)?;
        for pubkey in &self.contributions {
            pubkey.write(&mut writer)?;
        }

        Ok(())
    }

    pub fn cs_hash(&self) -> &[u8; 64] {
        &self.cs_hash
    }
}

// TODO: make this compatible with ts1
// fn keypair_ts1(mut rng: impl rand_ts1::RngCore, ...)
fn keypair(
    mut rng: impl RngCore,
    prev_cs_hash: &[u8; 64],
    prev_contributions: &[PublicKey],
    prev_delta_g1: &G1Affine,
) -> (PublicKey, PrivateKey) {
    // Sample random delta
    // TODO: make this compatible with ts1
    // let delta = rand_fr_ts1(&mut rng);
    let delta = Fr::random(&mut rng);

    // Compute delta s-pair in G1
    // TODO: make this compatible with ts1
    // let s = rand_g1_ts1(&mut rng).to_affine();
    let s = G1Projective::random(&mut rng).to_affine();
    let s_delta: G1Affine = (s * delta).to_affine();

    // H(cs_hash | <previous pubkeys> | s | s_delta)
    let h = {
        let sink = io::sink();
        let mut sink = HashWriter::new(sink);

        sink.write_all(prev_cs_hash).unwrap();
        for pubkey in prev_contributions {
            pubkey.write(&mut sink).unwrap();
        }
        sink.write_all(&s.to_uncompressed()).unwrap();
        sink.write_all(&s_delta.to_uncompressed()).unwrap();

        sink.into_hash()
    };

    // This avoids making a weird assumption about the hash into the
    // group.
    let transcript = h;

    // Compute delta s-pair in G2
    // TODO: make this compatible with ts1
    // let r: G2Affine = hash_to_g2_ts1(&h).to_affine();
    let r: G2Affine = hash_to_g2(&h).to_affine();
    let r_delta: G2Affine = (r * delta).to_affine();

    // Update `delta_g1`.
    let delta_after = (prev_delta_g1 * delta).to_affine();

    (
        PublicKey {
            delta_after,
            s,
            s_delta,
            r_delta,
            transcript,
        },
        PrivateKey { delta },
    )
}

pub fn verify_contribution_small(
    before: &MPCSmall,
    after: &MPCSmall,
    ts1: bool,
) -> Result<[u8; 64], ()> {
    // The after params must contain exactly one additonal contribution.
    if before.contributions.len() + 1 != after.contributions.len() {
        error!(
            "phase2::verify_contribution_small() non-sequential contributions:
            before.contributions.len()={}, \
            after.contributions.len()={}",
            before.contributions.len(),
            after.contributions.len()
        );
        return Err(());
    }

    // Previous participant public keys should not change.
    if before.contributions != after.contributions[..after.contributions.len() - 1] {
        error!("phase2::verify_contribution_small() previous public keys have changed");
        return Err(());
    }

    let before_is_initial = before.contributions.is_empty();
    let after_pubkey = after.contributions.last().unwrap();

    // Check that the before params' `delta_g1` and `delta_after` are the same value.
    if before_is_initial {
        if before.delta_g1 != G1Affine::generator() || before.delta_g2 != G2Affine::generator() {
            error!(
                "phase2::verify_contribution_small() initial params do not have identity deltas"
            );
            return Err(());
        }
    } else {
        let before_pubkey = before.contributions.last().unwrap();
        if before.delta_g1 != before_pubkey.delta_after {
            error!("phase2::verify_contribution_small() before params' delta_g1 and delta_after are not equal");
            return Err(());
        }
    };
    // Check that the after params' `delta_g1` and `delta_after` are the same value.
    if after.delta_g1 != after_pubkey.delta_after {
        error!("phase2::verify_contribution_small() after params' delta_g1 and delta_after are not equal");
        return Err(());
    }

    // h and l will change from the contribution, but should have same length.
    if before.h.len() != after.h.len() {
        error!("phase2::verify_contribution_small() length of h has changed");
        return Err(());
    }
    if before.l.len() != after.l.len() {
        error!("phase2::verify_contribution_small() length of l has changed");
        return Err(());
    }

    // cs_hash should be the same.
    if before.cs_hash != after.cs_hash {
        error!("phase2::verify_contribution_small() cs_hash has changed");
        return Err(());
    }

    // Calculate the expected after params transcript.
    let sink = io::sink();
    let mut sink = HashWriter::new(sink);
    sink.write_all(&before.cs_hash).unwrap();
    for pubkey in &before.contributions {
        pubkey.write(&mut sink).unwrap();
    }
    sink.write_all(&after_pubkey.s.to_uncompressed()).unwrap();
    sink.write_all(&after_pubkey.s_delta.to_uncompressed())
        .unwrap();
    let calculated_after_transcript = sink.into_hash();

    // Check the after params transcript against its calculated transcript.
    if after_pubkey.transcript != calculated_after_transcript {
        error!("phase2::verify_contribution_small() inconsistent transcript");
        return Err(());
    }

    // Filecoin's first and second trusted-setups used a different `hash_to_g2` algorithm
    let after_r = if ts1 {
        hash_to_g2_ts1(&after_pubkey.transcript).to_affine()
    } else {
        hash_to_g2(&after_pubkey.transcript).to_affine()
    };

    // Check the signature of knowledge. Check that the participant's r and s were shifted by the
    // same factor.
    if !same_ratio(
        (after_r, after_pubkey.r_delta),
        (after_pubkey.s, after_pubkey.s_delta),
    ) {
        error!("phase2::verify_contribution_small() participant's r and s were shifted by different deltas");
        return Err(());
    }

    // Check that delta_g1 and r were shifted by the same factor.
    if !same_ratio(
        (before.delta_g1, after.delta_g1),
        (after_r, after_pubkey.r_delta),
    ) {
        error!("phase2::verify_contribution_small() participant's delta_g1 and r where shifted by different deltas");
        return Err(());
    }

    // Check that delta_g1 and delta_g2 were shifted by the same factor.
    if !same_ratio(
        (G1Affine::generator(), after.delta_g1),
        (G2Affine::generator(), after.delta_g2),
    ) {
        error!("phase2::verify_contribution_small() delta_g1 and delta_g2 were shifted by different deltas");
        return Err(());
    }

    // h and l queries should be updated with `delta^-1`.
    if !same_ratio(
        merge_pairs(&before.h, &after.h),
        (after.delta_g2, before.delta_g2), // reversed for inverse
    ) {
        error!("phase2::verify_contribution_small() h was not updated by delta^-1");
        return Err(());
    }
    if !same_ratio(
        merge_pairs(&before.l, &after.l),
        (after.delta_g2, before.delta_g2), // reversed for inverse
    ) {
        error!("phase2::verify_contribution_small() l was not updated by delta^-1");
        return Err(());
    }

    // Calculate the "after" participant's contribution hash.
    let sink = io::sink();
    let mut sink = HashWriter::new(sink);
    after_pubkey.write(&mut sink).unwrap();
    Ok(sink.into_hash())
}

// Deserializes a raw formatted G1Affine uncompressed point. Note that the raw format was only used
// by Filecon's first trusted-setup.
fn read_g1_raw<R: Read>(reader: &mut R, check_subgroup: bool) -> io::Result<G1Affine> {
    let mut buf = [0u8; 1];
    reader.read_exact(&mut buf)?;
    let first_byte = buf[0];
    let is_inf = first_byte == 1;

    let mut x_mont = [0u64; 6];
    for limb in x_mont.iter_mut().rev() {
        *limb = reader.read_u64::<BigEndian>()?;
    }
    let x = Fp::from_raw_unchecked(x_mont);

    let mut y_mont = [0u64; 6];
    for limb in y_mont.iter_mut().rev() {
        *limb = reader.read_u64::<BigEndian>()?;
    }
    let y = Fp::from_raw_unchecked(y_mont);

    // Note that `is_inf` is ignored here by `blstrs`.
    let affine = G1Affine::from_raw_unchecked(x, y, is_inf);

    if !bool::from(affine.is_on_curve()) {
        return Err(error_not_on_curve());
    }

    if affine.is_identity().into() {
        if !is_inf {
            warn!(
                "Deserialized `G1Affine` is point-at-infinity, however first byte is `{}` (and not
                `1` as expected), this may indicate mismatching serialization/deserialization
                formats",
                first_byte,
            );
        }
        return Err(error_point_at_inf());
    }

    if first_byte != 0 {
        warn!(
            "Deserialized `G1Affine` is not point-at-infinity, however first byte is `{}` (and not
            `0` as expected), this may indicate mismatching serialization/deserialization formats",
            first_byte,
        );
    }

    if check_subgroup && affine.is_torsion_free().into() {
        return Err(error_not_in_subgroup());
    }

    Ok(affine)
}

// Serializes a `G1Affine` uncompressed point using the non-raw format.
#[inline]
fn write_g1<W: Write>(writer: &mut W, g1: &G1Affine) -> io::Result<usize> {
    writer.write(&g1.to_uncompressed())
}

// Serializes a `G1Affine` uncompressed point using the raw format. Note that the raw format is only
// used by Filecoin's first trusted-setup.
#[inline]
fn write_g1_raw<W: Write>(writer: &mut W, g1: &G1Affine) -> io::Result<usize> {
    g1.write_raw(writer)
}
