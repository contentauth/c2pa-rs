// Copyright 2026 Adobe. All rights reserved.
// This file is licensed under the Apache License, Version 2.0 or the MIT license.

//! Read-only, seek-based extraction of catalog-associated credentials. This is
//! deliberately not a document renderer or a repair parser.

use std::{
    collections::{btree_map::Entry, BTreeMap, BTreeSet},
    io::SeekFrom,
};

use flate2::{Decompress, FlushDecompress, Status};
use weezl::{decode::Decoder, BitOrder, LzwStatus};

use crate::{asset_io::ReadSeek, Error, Result};

pub(super) const THRESHOLD: u64 = 64 * 1024 * 1024;
const WINDOW: usize = 256 * 1024;
const STRUCTURAL: usize = 8 * 1024 * 1024;
const XMP: usize = 4 * 1024 * 1024;
pub(super) const MANIFEST: usize = 32 * 1024 * 1024;
const ALLOCATION: usize = 64 * 1024 * 1024;
const READ_BYTES: u64 = 512 * 1024 * 1024;
const OPERATIONS: usize = 8192;
const ENTRIES: usize = 65_536;
const ENTRY_WORK: usize = 262_144;
const OBJECTS: usize = 4096;
const DEPTH: usize = 64;
const REVISIONS: usize = 64;
const TOKENS: usize = 262_144;
const FILTERS: usize = 8;

fn malformed(reason: &str) -> Error {
    Error::InvalidAsset(format!("PDF: {reason}"))
}

fn limit(reason: &str) -> Error {
    Error::PdfResourceLimit(reason.into())
}

fn unsupported(reason: &str) -> Error {
    Error::NotImplemented(format!("bounded PDF: {reason}"))
}

/// A conservative *cumulative* allocation ledger, not just a live-byte ledger:
/// retained syntax/index overhead is charged at 256 bytes per item, byte-vector
/// capacity before growth. Nothing is refunded, so repeated resolves cannot
/// bypass the aggregate bound. Decoder scratch and the read window are included.
#[derive(Default)]
struct Budget {
    allocation: usize,
    tokens: usize,
    entries: usize,
    objects: usize,
    operations: usize,
    read_bytes: u64,
    decode_work: usize,
}

impl Budget {
    fn allocate(&mut self, bytes: usize) -> Result<()> {
        self.allocation = self
            .allocation
            .checked_add(bytes)
            .filter(|n| *n <= ALLOCATION)
            .ok_or_else(|| limit("64 MiB aggregate allocation"))?;
        Ok(())
    }

    fn token(&mut self) -> Result<()> {
        self.tokens += 1;
        if self.tokens > TOKENS {
            return Err(limit("syntax token count"));
        }
        self.allocate(256)
    }

    fn append(&mut self, output: &mut Vec<u8>, bytes: &[u8], cap: usize) -> Result<()> {
        let length = output
            .len()
            .checked_add(bytes.len())
            .filter(|n| *n <= cap)
            .ok_or_else(|| limit("decoded stream size"))?;
        if length > output.capacity() {
            let capacity = length.max(output.capacity().saturating_mul(2)).min(cap);
            self.allocate(capacity - output.capacity())?;
            output
                .try_reserve_exact(capacity - output.len())
                .map_err(|_| Error::InsufficientMemory)?;
        }
        output.extend_from_slice(bytes);
        Ok(())
    }

    fn decode(&mut self, bytes: usize) -> Result<()> {
        self.decode_work = self
            .decode_work
            .checked_add(bytes)
            .filter(|n| *n <= 128 * 1024 * 1024)
            .ok_or_else(|| limit("cumulative decode work"))?;
        Ok(())
    }
}

struct Input<'a> {
    stream: &'a mut dyn ReadSeek,
    length: u64,
    position: u64,
    window_start: u64,
    window: Vec<u8>,
    budget: Budget,
}

impl<'a> Input<'a> {
    fn new(stream: &'a mut dyn ReadSeek) -> Result<Self> {
        let length = stream.seek(SeekFrom::End(0))?;
        let mut budget = Budget::default();
        budget.allocate(WINDOW)?;
        Ok(Self {
            stream,
            length,
            position: 0,
            window_start: 0,
            window: Vec::with_capacity(WINDOW),
            budget,
        })
    }

    fn seek(&mut self, offset: u64) -> Result<()> {
        if offset > self.length {
            return Err(malformed("offset outside file"));
        }
        self.position = offset;
        Ok(())
    }

    fn read_at(&mut self, offset: u64, bytes: &mut [u8]) -> Result<()> {
        if offset
            .checked_add(bytes.len() as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(malformed("truncated stream"));
        }
        self.budget.operations += 1;
        if self.budget.operations > OPERATIONS {
            return Err(limit("seek/read count"));
        }
        self.budget.read_bytes = self
            .budget
            .read_bytes
            .checked_add(bytes.len() as u64)
            .filter(|n| *n <= READ_BYTES)
            .ok_or_else(|| limit("cumulative encoded input"))?;
        self.stream.seek(SeekFrom::Start(offset))?;
        self.stream.read_exact(bytes)?;
        Ok(())
    }

    fn peek(&mut self) -> Result<Option<u8>> {
        if self.position == self.length {
            return Ok(None);
        }
        let relative = self.position.checked_sub(self.window_start);
        if let Some(index) = relative.filter(|n| *n < self.window.len() as u64) {
            return Ok(Some(self.window[index as usize]));
        }
        let count = (self.length - self.position).min(WINDOW as u64) as usize;
        // Temporarily move the reusable buffer out to avoid a second allocation.
        let mut window = std::mem::take(&mut self.window);
        window.resize(count, 0);
        let result = self.read_at(self.position, &mut window);
        self.window_start = self.position;
        self.window = window;
        result?;
        Ok(self.window.first().copied())
    }

    fn byte(&mut self) -> Result<u8> {
        let byte = self.peek()?.ok_or_else(|| malformed("unexpected EOF"))?;
        self.position += 1;
        Ok(byte)
    }

    fn whitespace(&mut self) -> Result<()> {
        let start = self.position;
        loop {
            if self.position - start > WINDOW as u64 {
                return Err(limit("whitespace/comment scan"));
            }
            match self.peek()? {
                Some(b) if white(b) => self.position += 1,
                Some(b'%') => {
                    while let Some(b) = self.peek()? {
                        self.position += 1;
                        if self.position - start > WINDOW as u64 {
                            return Err(limit("comment scan"));
                        }
                        if matches!(b, b'\r' | b'\n') {
                            break;
                        }
                    }
                }
                _ => return Ok(()),
            }
        }
    }

    fn word(&mut self) -> Result<Vec<u8>> {
        self.whitespace()?;
        let mut word = Vec::with_capacity(64);
        self.budget.allocate(64)?;
        while let Some(b) = self.peek()? {
            if delimiter(b) {
                break;
            }
            if word.len() == 64 {
                return Err(limit("token length"));
            }
            word.push(self.byte()?);
        }
        if word.is_empty() {
            return Err(malformed("expected token"));
        }
        Ok(word)
    }

    fn expect(&mut self, expected: &[u8]) -> Result<()> {
        if self.word()? != expected {
            return Err(malformed("unexpected token"));
        }
        Ok(())
    }

    fn integer(&mut self) -> Result<u64> {
        unsigned(&self.word()?)
    }

    fn bytes(&mut self, offset: u64, length: usize, cap: usize) -> Result<Vec<u8>> {
        if length > cap {
            return Err(limit("encoded stream size"));
        }
        if offset
            .checked_add(length as u64)
            .is_none_or(|end| end > self.length)
        {
            return Err(malformed("stream extent outside file"));
        }
        self.budget.allocate(length)?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(length)
            .map_err(|_| Error::InsufficientMemory)?;
        bytes.resize(length, 0);
        for (index, chunk) in bytes.chunks_mut(WINDOW).enumerate() {
            self.read_at(offset + (index * WINDOW) as u64, chunk)?;
        }
        Ok(bytes)
    }
}

fn white(b: u8) -> bool {
    matches!(b, 0 | b'\t' | b'\n' | 12 | b'\r' | b' ')
}

fn delimiter(b: u8) -> bool {
    white(b) || b"()<>[]{}/%".contains(&b)
}

fn unsigned(word: &[u8]) -> Result<u64> {
    if word.is_empty() || !word.iter().all(u8::is_ascii_digit) {
        return Err(malformed("expected nonnegative integer"));
    }
    word.iter().try_fold(0u64, |n, b| {
        n.checked_mul(10)
            .and_then(|n| n.checked_add((b - b'0') as u64))
            .ok_or_else(|| malformed("integer overflow"))
    })
}

fn hex(b: u8) -> Result<u8> {
    (b as char)
        .to_digit(16)
        .map(|n| n as u8)
        .ok_or_else(|| malformed("invalid hexadecimal digit"))
}

fn marker_on_line(bytes: &[u8], offset: usize) -> bool {
    let line = bytes[..offset]
        .iter()
        .rposition(|b| matches!(b, b'\r' | b'\n'))
        .map_or(0, |position| position + 1);
    bytes[line..offset].iter().all(|b| white(*b))
}

type Id = (u32, u16);
type Dict = BTreeMap<Vec<u8>, Value>;

#[derive(Debug)]
enum Value {
    Null,
    Bool,
    Integer(i64),
    Real,
    Text,
    Name(Vec<u8>),
    Array(Vec<Value>),
    Dict(Dict),
    Reference(Id),
}

impl Value {
    fn number(&self) -> Result<u64> {
        match self {
            Self::Integer(n) if *n >= 0 => Ok(*n as u64),
            _ => Err(malformed("expected nonnegative integer")),
        }
    }

    fn dict(self) -> Result<Dict> {
        match self {
            Self::Dict(dict) => Ok(dict),
            _ => Err(malformed("expected dictionary")),
        }
    }

    fn array(self) -> Result<Vec<Value>> {
        match self {
            Self::Array(array) => Ok(array),
            _ => Err(malformed("expected array")),
        }
    }

    fn name(&self, name: &[u8]) -> bool {
        matches!(self, Self::Name(n) if n == name)
    }
}

fn parse(input: &mut Input<'_>, depth: usize) -> Result<Value> {
    if depth > DEPTH {
        return Err(limit("object nesting depth"));
    }
    input.budget.token()?;
    input.whitespace()?;
    let start = input.position;
    let value = match input.byte()? {
        b'/' => {
            let mut name = Vec::new();
            while let Some(b) = input.peek()? {
                if delimiter(b) {
                    break;
                }
                if name.len() >= 4096 {
                    return Err(limit("name length"));
                }
                let b = input.byte()?;
                let b = if b == b'#' {
                    (hex(input.byte()?)? << 4) | hex(input.byte()?)?
                } else {
                    b
                };
                input.budget.allocate(2)?;
                name.push(b);
            }
            Value::Name(name)
        }
        b'[' => {
            let mut values = Vec::new();
            loop {
                input.whitespace()?;
                if input.peek()? == Some(b']') {
                    input.position += 1;
                    break;
                }
                if values.len() >= 16_384 {
                    return Err(limit("array length"));
                }
                values.push(parse(input, depth + 1)?);
                if input.position - start > WINDOW as u64 {
                    return Err(limit("array encoded size"));
                }
            }
            Value::Array(values)
        }
        b'<' if input.peek()? == Some(b'<') => {
            input.position += 1;
            let mut dict = Dict::new();
            loop {
                input.whitespace()?;
                if input.peek()? == Some(b'>') {
                    input.position += 1;
                    if input.byte()? != b'>' {
                        return Err(malformed("dictionary terminator"));
                    }
                    break;
                }
                if dict.len() >= 16_384 {
                    return Err(limit("dictionary length"));
                }
                let Value::Name(key) = parse(input, depth + 1)? else {
                    return Err(malformed("dictionary key is not a name"));
                };
                let value = parse(input, depth + 1)?;
                if dict.insert(key, value).is_some() {
                    return Err(malformed("duplicate dictionary key"));
                }
                if input.position - start > WINDOW as u64 {
                    return Err(limit("dictionary encoded size"));
                }
            }
            Value::Dict(dict)
        }
        b'<' => {
            loop {
                let b = input.byte()?;
                if b == b'>' {
                    break;
                }
                if !white(b) {
                    hex(b)?;
                }
                if input.position - start > WINDOW as u64 {
                    return Err(limit("string length"));
                }
            }
            Value::Text
        }
        b'(' => {
            let mut nesting = 1;
            while nesting > 0 {
                match input.byte()? {
                    b'\\' => {
                        input.byte()?;
                    }
                    b'(' => nesting += 1,
                    b')' => nesting -= 1,
                    _ => {}
                }
                if nesting > DEPTH || input.position - start > WINDOW as u64 {
                    return Err(limit("string length/depth"));
                }
            }
            Value::Text
        }
        _ => {
            input.seek(start)?;
            let word = input.word()?;
            match word.as_slice() {
                b"null" => Value::Null,
                b"true" | b"false" => Value::Bool,
                _ => {
                    let text = std::str::from_utf8(&word)
                        .map_err(|_| malformed("invalid numeric token"))?;
                    if let Ok(n) = text.parse::<i64>() {
                        let after = input.position;
                        if n >= 0 {
                            // References are the only compound numeric token.
                            input.whitespace()?;
                            if input.peek()?.is_some_and(|b| b.is_ascii_digit()) {
                                let generation = input.integer()?;
                                input.whitespace()?;
                                if input.peek()? == Some(b'R') {
                                    input.expect(b"R")?;
                                    return Ok(Value::Reference((
                                        u32::try_from(n)
                                            .map_err(|_| malformed("object id overflow"))?,
                                        u16::try_from(generation)
                                            .map_err(|_| malformed("generation overflow"))?,
                                    )));
                                }
                            }
                            input.seek(after)?;
                        }
                        Value::Integer(n)
                    } else if !text.contains(['e', 'E'])
                        && text.parse::<f64>().is_ok_and(|n| n.is_finite())
                    {
                        Value::Real
                    } else {
                        return Err(malformed("invalid object token"));
                    }
                }
            }
        }
    };
    if input.position - start > WINDOW as u64 {
        return Err(limit("structural object encoded size"));
    }
    Ok(value)
}

struct Object {
    value: Value,
    stream: Option<u64>,
}

#[derive(Clone, Copy, Debug)]
enum Xref {
    Free,
    Offset(u64, u16),
    Compressed(u32, u32),
}

struct Pdf<'a> {
    input: Input<'a>,
    index: BTreeMap<u32, Xref>,
    root: Id,
    size: u64,
    resolving: Vec<Id>,
}

impl<'a> Pdf<'a> {
    fn open(stream: &'a mut dyn ReadSeek) -> Result<Self> {
        let mut input = Input::new(stream)?;
        if input.length < 8 {
            return Err(malformed("missing PDF header"));
        }
        let mut header = [0u8; 8];
        input.read_at(0, &mut header)?;
        if !header.starts_with(b"%PDF-")
            || !header[5].is_ascii_digit()
            || header[6] != b'.'
            || !header[7].is_ascii_digit()
        {
            return Err(malformed("missing PDF header"));
        }
        let tail_len = input.length.min(WINDOW as u64) as usize;
        let tail_start = input.length - tail_len as u64;
        let tail = input.bytes(tail_start, tail_len, WINDOW)?;
        let eof = tail
            .windows(5)
            .rposition(|w| w == b"%%EOF")
            .ok_or_else(|| malformed("repair required: missing final EOF"))?;
        if tail[eof + 5..].iter().any(|b| !white(*b)) {
            return Err(malformed("non-whitespace after final EOF"));
        }
        if !marker_on_line(&tail, eof) {
            return Err(malformed("final EOF is not a line marker"));
        }
        let marker = tail[..eof]
            .windows(9)
            .rposition(|w| w == b"startxref")
            .ok_or_else(|| malformed("repair required: startxref outside bounded tail"))?;
        if !marker_on_line(&tail, marker) {
            return Err(malformed("startxref is not a line marker"));
        }
        let offset = tail[marker + 9..eof].trim_ascii();
        if offset.len() > 64 {
            return Err(limit("startxref numeric token"));
        }
        let offset = unsigned(offset)?;
        drop(tail);
        input.budget.allocate(DEPTH * std::mem::size_of::<Id>())?;
        let mut pdf = Self {
            input,
            index: BTreeMap::new(),
            root: (0, 0),
            size: 0,
            resolving: Vec::with_capacity(DEPTH),
        };
        pdf.xrefs(offset)?;
        Ok(pdf)
    }

    fn indirect(&mut self, offset: u64, expected: Option<Id>) -> Result<Object> {
        self.input.seek(offset)?;
        let id = (
            u32::try_from(self.input.integer()?).map_err(|_| malformed("object id overflow"))?,
            u16::try_from(self.input.integer()?).map_err(|_| malformed("generation overflow"))?,
        );
        if id.0 == 0 || expected.is_some_and(|expected| expected != id) {
            return Err(malformed("xref object id/generation mismatch"));
        }
        self.input.expect(b"obj")?;
        let value = parse(&mut self.input, 0)?;
        let next = self.input.word()?;
        let stream = if next == b"stream" {
            if !matches!(value, Value::Dict(_)) {
                return Err(malformed("stream dictionary missing"));
            }
            match self.input.byte()? {
                b'\n' => {}
                b'\r' => {
                    if self.input.byte()? != b'\n' {
                        return Err(malformed("stream EOL"));
                    }
                }
                _ => return Err(malformed("stream EOL")),
            }
            Some(self.input.position)
        } else {
            if next != b"endobj" {
                return Err(malformed("missing endobj"));
            }
            None
        };
        Ok(Object { value, stream })
    }

    fn xrefs(&mut self, mut offset: u64) -> Result<()> {
        let mut visited = BTreeSet::new();
        let mut root = None;
        for _ in 0..REVISIONS {
            self.input.budget.allocate(256)?;
            if offset == 0 || offset >= self.input.length || !visited.insert(offset) {
                return Err(malformed("invalid/cyclic xref offset"));
            }
            self.input.seek(offset)?;
            let mut revision = BTreeMap::new();
            let mut trailer = if self.input.peek()? == Some(b'x') {
                self.table(&mut revision)?
            } else {
                self.xref_stream(offset, &mut revision)?
            };
            if let Some(hybrid) = trailer.remove(b"XRefStm".as_slice()) {
                let hybrid = hybrid.number()?;
                if hybrid == 0 || hybrid >= self.input.length || !visited.insert(hybrid) {
                    return Err(malformed("invalid/cyclic hybrid xref"));
                }
                let mut stream_trailer = self.xref_stream(hybrid, &mut revision)?;
                let stream_prev = stream_trailer.remove(b"Prev".as_slice());
                if let Some(stream_prev) = stream_prev {
                    match trailer.get(b"Prev".as_slice()) {
                        Some(prev) if prev.number()? != stream_prev.number()? => {
                            return Err(malformed("inconsistent hybrid Prev"));
                        }
                        None => {
                            trailer.insert(b"Prev".to_vec(), stream_prev);
                        }
                        _ => {}
                    }
                }
                if stream_trailer
                    .get(b"Encrypt".as_slice())
                    .is_some_and(|v| !matches!(v, Value::Null))
                {
                    return Err(unsupported("encryption"));
                }
                if !trailer.contains_key(b"Root".as_slice()) {
                    if let Some(root) = stream_trailer.remove(b"Root".as_slice()) {
                        trailer.insert(b"Root".to_vec(), root);
                    }
                }
            }
            if trailer
                .get(b"Encrypt".as_slice())
                .is_some_and(|v| !matches!(v, Value::Null))
            {
                return Err(unsupported("encryption"));
            }
            let size = required(&mut trailer, b"Size")?.number()?;
            if size == 0 || size > u32::MAX as u64 + 1 {
                return Err(malformed("invalid xref Size"));
            }
            if self.size == 0 {
                self.size = size;
            }
            if revision.keys().any(|id| *id as u64 >= size) {
                return Err(malformed("xref id exceeds Size"));
            }
            if root.is_none() {
                if let Some(value) = trailer.remove(b"Root".as_slice()) {
                    let Value::Reference(id) = value else {
                        return Err(malformed("trailer Root must be indirect"));
                    };
                    root = Some(id);
                }
            }
            for (id, entry) in revision {
                if let Entry::Vacant(slot) = self.index.entry(id) {
                    if self.input.budget.entries >= ENTRIES {
                        return Err(limit("effective xref entry count"));
                    }
                    self.input.budget.entries += 1;
                    self.input.budget.allocate(256)?;
                    slot.insert(entry);
                }
            }
            match trailer.remove(b"Prev".as_slice()) {
                Some(prev) => offset = prev.number()?,
                None => {
                    self.root = root.ok_or_else(|| malformed("missing trailer Root"))?;
                    if self.root.0 == 0 || self.root.0 as u64 >= self.size {
                        return Err(malformed("Root outside effective xref Size"));
                    }
                    return Ok(());
                }
            }
        }
        Err(limit("incremental revision count"))
    }

    fn entry(
        &mut self,
        index: &mut BTreeMap<u32, Xref>,
        id: u32,
        entry: Xref,
        replace: bool,
    ) -> Result<()> {
        self.input.budget.token()?;
        if self.input.budget.tokens > ENTRY_WORK {
            return Err(limit("cumulative xref entries"));
        }
        if !replace && index.contains_key(&id) {
            return Err(malformed("overlapping xref subsections"));
        }
        if index.len() >= ENTRIES && !index.contains_key(&id) {
            return Err(limit("revision xref entry count"));
        }
        if let Xref::Offset(offset, _) = entry {
            if offset == 0 || offset >= self.input.length {
                return Err(malformed("xref offset outside file"));
            }
        }
        index.insert(id, entry);
        Ok(())
    }

    fn table(&mut self, index: &mut BTreeMap<u32, Xref>) -> Result<Dict> {
        self.input.expect(b"xref")?;
        loop {
            self.input.whitespace()?;
            if self.input.peek()? == Some(b't') {
                self.input.expect(b"trailer")?;
                return parse(&mut self.input, 0)?.dict();
            }
            let first = self.input.integer()?;
            let count = self.input.integer()?;
            let end = first
                .checked_add(count)
                .filter(|end| *end <= u32::MAX as u64 + 1)
                .ok_or_else(|| malformed("xref subsection overflow"))?;
            if count > ENTRIES as u64 {
                return Err(limit("xref subsection count"));
            }
            for id in first..end {
                let offset = self.input.integer()?;
                let generation = u16::try_from(self.input.integer()?)
                    .map_err(|_| malformed("xref generation overflow"))?;
                let entry = match self.input.word()?.as_slice() {
                    b"n" if id != 0 && generation != u16::MAX => Xref::Offset(offset, generation),
                    b"f" => Xref::Free,
                    _ => return Err(malformed("invalid xref entry")),
                };
                self.entry(index, id as u32, entry, false)?;
            }
        }
    }

    fn xref_stream(&mut self, offset: u64, index: &mut BTreeMap<u32, Xref>) -> Result<Dict> {
        let object = self.indirect(offset, None)?;
        let mut dict = object.value.dict()?;
        if !required(&mut dict, b"Type")?.name(b"XRef") {
            return Err(malformed("startxref does not point to XRef"));
        }
        let widths = required(&mut dict, b"W")?.array()?;
        if widths.len() != 3 {
            return Err(malformed("xref W length"));
        }
        let mut w = [0usize; 3];
        for (target, value) in w.iter_mut().zip(widths) {
            *target = usize::try_from(value.number()?).map_err(|_| malformed("xref W"))?;
            if *target > 8 {
                return Err(unsupported("xref field wider than 64 bits"));
            }
        }
        let width = w.iter().sum::<usize>();
        if width == 0 {
            return Err(malformed("empty xref W"));
        }
        let size = dict
            .get(b"Size".as_slice())
            .ok_or_else(|| malformed("missing xref Size"))?
            .number()?;
        let ranges = match dict.remove(b"Index".as_slice()) {
            Some(value) => value.array()?,
            None => vec![
                Value::Integer(0),
                Value::Integer(i64::try_from(size).map_err(|_| malformed("xref Size overflow"))?),
            ],
        };
        if ranges.len() % 2 != 0 {
            return Err(malformed("xref Index length"));
        }
        let mut total = 0usize;
        self.input.budget.allocate(ranges.len() * 16)?;
        let mut intervals = Vec::with_capacity(ranges.len() / 2);
        for pair in ranges.as_chunks::<2>().0 {
            let first = pair[0].number()?;
            let count = pair[1].number()?;
            let end = first
                .checked_add(count)
                .filter(|end| *end <= size && *end <= u32::MAX as u64 + 1)
                .ok_or_else(|| malformed("xref Index overflow"))?;
            intervals.push((first, end));
            total = total
                .checked_add(usize::try_from(count).map_err(|_| limit("xref count"))?)
                .filter(|n| *n <= ENTRIES)
                .ok_or_else(|| limit("xref stream count"))?;
        }
        intervals.sort_unstable();
        if intervals.windows(2).any(|pair| pair[1].0 < pair[0].1) {
            return Err(malformed("overlapping xref Index"));
        }
        // Xref stream keys are direct per ISO 32000 §7.5.8.2; an indirect Length
        // cannot be resolved before this very index exists.
        if matches!(dict.get(b"Length".as_slice()), Some(Value::Reference(_))) {
            return Err(unsupported("indirect xref stream Length"));
        }
        let bytes = self.stream_bytes(&mut dict, object.stream, STRUCTURAL)?;
        let expected = total
            .checked_mul(width)
            .ok_or_else(|| malformed("xref length overflow"))?;
        if bytes.len() != expected {
            return Err(malformed("xref stream length does not match W/Index"));
        }
        let mut entries = bytes.chunks_exact(width);
        for pair in ranges.as_chunks::<2>().0 {
            let first = pair[0].number()?;
            let count = pair[1].number()?;
            for id in first..first + count {
                let bytes = entries
                    .next()
                    .ok_or_else(|| malformed("truncated xref stream"))?;
                let mut values = [0u64; 3];
                let mut start = 0;
                for (i, width) in w.iter().enumerate() {
                    for b in &bytes[start..start + width] {
                        values[i] = (values[i] << 8) | *b as u64;
                    }
                    start += width;
                }
                let kind = if w[0] == 0 { 1 } else { values[0] };
                let entry = match kind {
                    0 => {
                        u16::try_from(values[2])
                            .map_err(|_| malformed("free generation overflow"))?;
                        Xref::Free
                    }
                    1 if id != 0 && values[2] < u16::MAX as u64 => Xref::Offset(
                        values[1],
                        u16::try_from(values[2]).map_err(|_| malformed("generation overflow"))?,
                    ),
                    2 if id != 0 => Xref::Compressed(
                        u32::try_from(values[1]).map_err(|_| malformed("ObjStm id overflow"))?,
                        u32::try_from(values[2]).map_err(|_| malformed("ObjStm index overflow"))?,
                    ),
                    _ => return Err(unsupported("unknown xref entry type")),
                };
                self.entry(index, id as u32, entry, true)?;
            }
        }
        Ok(dict)
    }

    fn resolve(&mut self, value: Value) -> Result<Object> {
        let Value::Reference(id) = value else {
            return Ok(Object {
                value,
                stream: None,
            });
        };
        if self.resolving.len() >= DEPTH {
            return Err(limit("indirect object depth"));
        }
        if self.resolving.contains(&id) {
            return Err(malformed("cyclic indirect reference"));
        }
        self.input.budget.objects += 1;
        if self.input.budget.objects > OBJECTS {
            return Err(limit("object resolution count"));
        }
        self.resolving.push(id);
        let result = self.resolve_id(id);
        self.resolving.pop();
        result
    }

    fn resolve_id(&mut self, id: Id) -> Result<Object> {
        if id.0 == 0 || id.0 as u64 >= self.size {
            return Err(malformed("reference outside effective xref Size"));
        }
        let entry = self
            .index
            .get(&id.0)
            .copied()
            .ok_or_else(|| malformed("reference missing from xref"))?;
        let object = match entry {
            Xref::Offset(offset, generation) if generation == id.1 => {
                self.indirect(offset, Some(id))?
            }
            Xref::Compressed(container, slot) if id.1 == 0 => {
                self.compressed(id.0, container, slot)?
            }
            _ => return Err(malformed("reference to free object or wrong generation")),
        };
        if matches!(object.value, Value::Reference(_)) {
            if object.stream.is_some() {
                return Err(malformed("reference stream"));
            }
            self.resolve(object.value)
        } else {
            Ok(object)
        }
    }

    fn compressed(&mut self, target: u32, container: u32, slot: u32) -> Result<Object> {
        let Some(Xref::Offset(_, generation)) = self.index.get(&container).copied() else {
            return Err(malformed("ObjStm must be an uncompressed object"));
        };
        let object = self.resolve(Value::Reference((container, generation)))?;
        let mut dict = object.value.dict()?;
        if !required(&mut dict, b"Type")?.name(b"ObjStm") {
            return Err(malformed("compressed object container is not ObjStm"));
        }
        let count = required(&mut dict, b"N")?.number()?;
        let first = required(&mut dict, b"First")?.number()?;
        if count == 0 || slot as u64 >= count {
            return Err(malformed("ObjStm N/index"));
        }
        if count > OBJECTS as u64 {
            return Err(limit("ObjStm N"));
        }
        let bytes = self.stream_bytes(&mut dict, object.stream, STRUCTURAL)?;
        let first = usize::try_from(first).map_err(|_| malformed("ObjStm First overflow"))?;
        if first >= bytes.len() {
            return Err(malformed("ObjStm First outside stream"));
        }
        let mut cursor = std::io::Cursor::new(bytes.as_slice());
        let mut input = Input::new(&mut cursor)?;
        // Account the temporary input's window and syntax in the same ledger.
        input.budget = std::mem::take(&mut self.input.budget);
        input.budget.allocate(WINDOW)?;
        let result = (|| {
            let mut ids = BTreeSet::new();
            let mut selected = None;
            let mut previous = None;
            let mut selected_end = bytes.len() - first;
            for index in 0..count {
                let id = u32::try_from(input.integer()?)
                    .map_err(|_| malformed("ObjStm object id overflow"))?;
                let offset = usize::try_from(input.integer()?)
                    .map_err(|_| malformed("ObjStm offset overflow"))?;
                input.budget.allocate(256)?;
                if id == 0
                    || !ids.insert(id)
                    || offset >= bytes.len() - first
                    || previous.is_some_and(|previous| offset <= previous)
                {
                    return Err(malformed("invalid ObjStm header"));
                }
                if index == slot as u64 {
                    if id != target {
                        return Err(malformed("ObjStm index/id mismatch"));
                    }
                    selected = Some(offset);
                } else if index == slot as u64 + 1 {
                    selected_end = offset;
                }
                previous = Some(offset);
            }
            input.whitespace()?;
            if input.position != first as u64 {
                return Err(malformed("ObjStm N/First mismatch"));
            }
            input
                .seek((first + selected.ok_or_else(|| malformed("missing ObjStm slot"))?) as u64)?;
            let value = parse(&mut input, 0)?;
            input.whitespace()?;
            if input.position != (first + selected_end) as u64 {
                return Err(malformed("ObjStm object boundary"));
            }
            Ok(Object {
                value,
                stream: None,
            })
        })();
        self.input.budget = std::mem::take(&mut input.budget);
        result
    }

    fn field(&mut self, dict: &mut Dict, key: &[u8]) -> Result<Value> {
        let value = required(dict, key)?;
        self.plain(value)
    }

    fn plain(&mut self, value: Value) -> Result<Value> {
        let object = self.resolve(value)?;
        if object.stream.is_some() {
            return Err(malformed("stream used as a structural value"));
        }
        Ok(object.value)
    }

    fn stream_bytes(&mut self, dict: &mut Dict, start: Option<u64>, cap: usize) -> Result<Vec<u8>> {
        let start = start.ok_or_else(|| malformed("expected stream object"))?;
        if dict.contains_key(b"F".as_slice()) {
            return Err(unsupported("external stream data"));
        }
        let length = usize::try_from(self.field(dict, b"Length")?.number()?)
            .map_err(|_| malformed("stream length overflow"))?;
        let filters = match dict.remove(b"Filter".as_slice()) {
            None => Vec::new(),
            Some(value) => match self.plain(value)? {
                Value::Name(name) => vec![name],
                Value::Array(array) => array
                    .into_iter()
                    .map(|value| {
                        let value = self.plain(value)?;
                        match value {
                            Value::Name(name) => Ok(name),
                            _ => Err(malformed("invalid stream Filter")),
                        }
                    })
                    .collect::<Result<Vec<_>>>()?,
                _ => return Err(malformed("invalid stream Filter")),
            },
        };
        if filters.len() > FILTERS {
            return Err(limit("filter chain count"));
        }
        let params = match dict.remove(b"DecodeParms".as_slice()) {
            None | Some(Value::Null) => (0..filters.len()).map(|_| Value::Null).collect(),
            Some(value) => match self.plain(value)? {
                Value::Dict(dict) if filters.len() == 1 => vec![Value::Dict(dict)],
                Value::Array(array) if array.len() == filters.len() => array,
                _ => return Err(malformed("DecodeParms does not match Filter")),
            },
        };
        let encoded_cap = if filters.is_empty() { cap } else { STRUCTURAL };
        let mut bytes = self.input.bytes(start, length, encoded_cap)?;
        self.input.seek(
            start
                .checked_add(length as u64)
                .ok_or_else(|| malformed("stream end overflow"))?,
        )?;
        self.input.expect(b"endstream")?;
        self.input.expect(b"endobj")?;
        for (filter, param) in filters.into_iter().zip(params) {
            let param = self.plain(param)?;
            let param = match param {
                Value::Null => Dict::new(),
                Value::Dict(dict) => dict,
                _ => return Err(malformed("invalid DecodeParms")),
            };
            bytes = decode(&filter, &param, &bytes, cap, &mut self.input.budget)?;
        }
        if bytes.len() > cap {
            return Err(limit("decoded stream size"));
        }
        Ok(bytes)
    }

    fn catalog(&mut self) -> Result<Dict> {
        let object = self.resolve(Value::Reference(self.root))?;
        if object.stream.is_some() {
            return Err(malformed("catalog cannot be a stream"));
        }
        let mut dict = object.value.dict()?;
        if !self.field(&mut dict, b"Type")?.name(b"Catalog") {
            return Err(malformed("Root is not Catalog"));
        }
        Ok(dict)
    }

    fn manifest(&mut self, cap: usize) -> Result<Vec<u8>> {
        let mut catalog = self.catalog()?;
        let Some(af) = catalog.remove(b"AF".as_slice()) else {
            return Err(Error::JumbfNotFound);
        };
        let af = self.plain(af)?.array()?;
        let mut found = None;
        for file in af {
            let mut file = self.plain(file)?.dict()?;
            let Some(relationship) = file.remove(b"AFRelationship".as_slice()) else {
                continue;
            };
            let relationship = self.plain(relationship)?;
            if !matches!(relationship, Value::Name(_)) {
                return Err(malformed("AFRelationship is not a name"));
            }
            if !relationship.name(b"C2PA_Manifest") {
                continue;
            }
            if found.is_some() {
                return Err(Error::TooManyManifestStores);
            }
            let mut ef = self.field(&mut file, b"EF")?.dict()?;
            let object = self.resolve(required(&mut ef, b"F")?)?;
            let mut dict = object.value.dict()?;
            let bytes = self.stream_bytes(&mut dict, object.stream, cap)?;
            if bytes.is_empty() {
                return Err(malformed("empty C2PA manifest stream"));
            }
            found = Some(bytes);
        }
        found.ok_or(Error::JumbfNotFound)
    }

    fn xmp(&mut self) -> Result<Option<String>> {
        let mut catalog = self.catalog()?;
        let Some(metadata) = catalog.remove(b"Metadata".as_slice()) else {
            return Ok(None);
        };
        let object = self.resolve(metadata)?;
        let mut dict = object.value.dict()?;
        if !self.field(&mut dict, b"Subtype")?.name(b"XML") {
            return Err(unsupported("non-XML catalog Metadata"));
        }
        let bytes = self.stream_bytes(&mut dict, object.stream, XMP)?;
        String::from_utf8(bytes)
            .map(Some)
            .map_err(|_| malformed("XMP is not UTF-8"))
    }
}

fn required(dict: &mut Dict, key: &[u8]) -> Result<Value> {
    dict.remove(key)
        .ok_or_else(|| malformed("required dictionary key missing"))
}

pub(super) fn read_manifest(stream: &mut dyn ReadSeek, cap: usize) -> Result<Vec<u8>> {
    Pdf::open(stream)?.manifest(cap.min(MANIFEST))
}

pub(super) fn read_xmp(stream: &mut dyn ReadSeek) -> Result<Option<String>> {
    Pdf::open(stream)?.xmp()
}

fn parameter(dict: &Dict, key: &[u8], default: u64) -> Result<u64> {
    match dict.get(key) {
        None => Ok(default),
        Some(value) => value.number(),
    }
}

fn decode(
    filter: &[u8],
    params: &Dict,
    input: &[u8],
    cap: usize,
    budget: &mut Budget,
) -> Result<Vec<u8>> {
    budget.decode(input.len())?;
    let mut output = Vec::new();
    match filter {
        b"FlateDecode" | b"Fl" => {
            budget.allocate(64 * 1024)?;
            let mut decoder = Decompress::new(true);
            let mut buffer = [0u8; 16 * 1024];
            let mut consumed = 0;
            loop {
                let before_in = decoder.total_in();
                let before_out = decoder.total_out();
                let status = decoder
                    .decompress(&input[consumed..], &mut buffer, FlushDecompress::None)
                    .map_err(|_| malformed("corrupt Flate stream"))?;
                let read = (decoder.total_in() - before_in) as usize;
                let written = (decoder.total_out() - before_out) as usize;
                consumed += read;
                budget.append(&mut output, &buffer[..written], cap)?;
                if status == Status::StreamEnd {
                    if consumed != input.len() {
                        return Err(malformed("trailing Flate data"));
                    }
                    break;
                }
                if read == 0 && written == 0 {
                    return Err(malformed("truncated Flate stream"));
                }
            }
        }
        b"LZWDecode" | b"LZW" => {
            budget.allocate(512 * 1024)?;
            let early = parameter(params, b"EarlyChange", 1)?;
            let mut decoder = match early {
                0 => Decoder::new(BitOrder::Msb, 8),
                1 => Decoder::with_tiff_size_switch(BitOrder::Msb, 8),
                _ => return Err(malformed("invalid LZW EarlyChange")),
            };
            let mut buffer = [0u8; 16 * 1024];
            let mut consumed = 0;
            loop {
                let result = decoder.decode_bytes(&input[consumed..], &mut buffer);
                consumed += result.consumed_in;
                budget.append(&mut output, &buffer[..result.consumed_out], cap)?;
                match result.status {
                    Ok(LzwStatus::Done) => break,
                    Err(_) => return Err(malformed("corrupt LZW stream")),
                    _ if result.consumed_in == 0 && result.consumed_out == 0 => {
                        return Err(malformed("truncated LZW stream"));
                    }
                    _ => {}
                }
            }
        }
        b"ASCIIHexDecode" | b"AHx" => {
            let mut high = None;
            let mut ended = false;
            for b in input {
                if white(*b) {
                    continue;
                }
                if ended {
                    return Err(malformed("trailing ASCIIHex data"));
                }
                if *b == b'>' {
                    ended = true;
                    continue;
                }
                let nibble = hex(*b)?;
                match high.take() {
                    Some(high) => budget.append(&mut output, &[(high << 4) | nibble], cap)?,
                    None => high = Some(nibble),
                }
            }
            if !ended {
                return Err(malformed("missing ASCIIHex EOD"));
            }
            if let Some(high) = high {
                budget.append(&mut output, &[high << 4], cap)?;
            }
        }
        b"ASCII85Decode" | b"A85" => {
            let mut group = 0u32;
            let mut count = 0usize;
            let mut cursor = 0;
            let mut ended = false;
            while cursor < input.len() {
                let b = input[cursor];
                cursor += 1;
                if white(b) {
                    continue;
                }
                if b == b'~' {
                    if input.get(cursor) != Some(&b'>') {
                        return Err(malformed("ASCII85 EOD"));
                    }
                    cursor += 1;
                    ended = true;
                    break;
                }
                if b == b'z' && count == 0 {
                    budget.append(&mut output, &[0; 4], cap)?;
                    continue;
                }
                if !(b'!'..=b'u').contains(&b) {
                    return Err(malformed("invalid ASCII85 digit"));
                }
                group = group
                    .checked_mul(85)
                    .and_then(|n| n.checked_add((b - b'!') as u32))
                    .ok_or_else(|| malformed("ASCII85 group overflow"))?;
                count += 1;
                if count == 5 {
                    budget.append(&mut output, &group.to_be_bytes(), cap)?;
                    group = 0;
                    count = 0;
                }
            }
            if !ended || input[cursor..].iter().any(|b| !white(*b)) || count == 1 {
                return Err(malformed("invalid ASCII85 termination"));
            }
            if count > 1 {
                for _ in count..5 {
                    group = group
                        .checked_mul(85)
                        .and_then(|n| n.checked_add(84))
                        .ok_or_else(|| malformed("ASCII85 group overflow"))?;
                }
                budget.append(&mut output, &group.to_be_bytes()[..count - 1], cap)?;
            }
        }
        b"RunLengthDecode" | b"RL" => {
            let mut cursor = 0;
            let mut ended = false;
            while let Some(length) = input.get(cursor).copied() {
                cursor += 1;
                match length {
                    128 => {
                        ended = true;
                        break;
                    }
                    0..=127 => {
                        let end = cursor + length as usize + 1;
                        let bytes = input
                            .get(cursor..end)
                            .ok_or_else(|| malformed("truncated RunLength stream"))?;
                        budget.append(&mut output, bytes, cap)?;
                        cursor = end;
                    }
                    _ => {
                        let byte = input
                            .get(cursor)
                            .ok_or_else(|| malformed("truncated RunLength stream"))?;
                        budget.append(&mut output, &[*byte; 128][..257 - length as usize], cap)?;
                        cursor += 1;
                    }
                }
            }
            if !ended || cursor != input.len() {
                return Err(malformed("invalid RunLength termination"));
            }
        }
        _ => return Err(unsupported("stream filter")),
    }
    budget.decode(output.len())?;
    if matches!(filter, b"FlateDecode" | b"Fl" | b"LZWDecode" | b"LZW") {
        predictor(output, params)
    } else if !params.is_empty() {
        Err(unsupported("DecodeParms on non-Flate/LZW filter"))
    } else {
        Ok(output)
    }
}

fn predictor(mut bytes: Vec<u8>, params: &Dict) -> Result<Vec<u8>> {
    let predictor = parameter(params, b"Predictor", 1)?;
    if predictor == 1 {
        return Ok(bytes);
    }
    let colors = parameter(params, b"Colors", 1)?;
    let columns = parameter(params, b"Columns", 1)?;
    let bits = parameter(params, b"BitsPerComponent", 8)?;
    if bits != 8 {
        return Err(unsupported("non-eight-bit structural predictor"));
    }
    let row = colors
        .checked_mul(columns)
        .filter(|n| *n > 0 && *n <= STRUCTURAL as u64)
        .ok_or_else(|| malformed("predictor row overflow"))? as usize;
    let colors = usize::try_from(colors).map_err(|_| malformed("predictor colors overflow"))?;
    if predictor == 2 {
        if !bytes.len().is_multiple_of(row) {
            return Err(malformed("truncated TIFF predictor row"));
        }
        for row in bytes.chunks_exact_mut(row) {
            for i in colors..row.len() {
                row[i] = row[i].wrapping_add(row[i - colors]);
            }
        }
        return Ok(bytes);
    }
    if !(10..=15).contains(&predictor) || !bytes.len().is_multiple_of(row + 1) {
        return Err(malformed("invalid PNG predictor rows"));
    }
    let rows = bytes.len() / (row + 1);
    for y in 0..rows {
        let source = y * (row + 1);
        let target = y * row;
        let filter = bytes[source];
        if filter > 4 || (predictor != 15 && filter as u64 != predictor - 10) {
            return Err(malformed("invalid PNG predictor filter"));
        }
        for x in 0..row {
            let left = if x >= colors {
                bytes[target + x - colors]
            } else {
                0
            };
            let above = if y > 0 { bytes[target + x - row] } else { 0 };
            let upper_left = if y > 0 && x >= colors {
                bytes[target + x - row - colors]
            } else {
                0
            };
            let prediction = match filter {
                0 => 0,
                1 => left,
                2 => above,
                3 => ((left as u16 + above as u16) / 2) as u8,
                4 => {
                    let p = left as i32 + above as i32 - upper_left as i32;
                    let a = (p - left as i32).abs();
                    let b = (p - above as i32).abs();
                    let c = (p - upper_left as i32).abs();
                    if a <= b && a <= c {
                        left
                    } else if b <= c {
                        above
                    } else {
                        upper_left
                    }
                }
                _ => unreachable!(),
            };
            bytes[target + x] = bytes[source + 1 + x].wrapping_add(prediction);
        }
    }
    bytes.truncate(rows * row);
    Ok(bytes)
}

#[cfg(test)]
#[path = "pdf_bounded_tests.rs"]
mod tests;
