use std::{
    cmp::min,
    collections::HashMap,
    io::{BufRead, BufReader, Cursor, Read, Seek, SeekFrom},
};

use anyhow::Result;
use serde::{Deserialize, Serialize};

// The function stream_histogram returns a HashMap that contains str as the key and the word frequency as the value.  The inputs
// are a Read stream containing a UTF-8 characters.
pub fn stream_histogram<R: Read>(reader: &mut R) -> Result<HashMap<String, usize>> {
    let mut output = HashMap::new();

    let mut buf_reader = BufReader::new(reader);
    let mut reader_str = String::new();
    buf_reader.read_to_string(&mut reader_str)?;

    let words = reader_str.split_whitespace().collect::<Vec<&str>>();
    for word in words {
        *output.entry(word.to_string()).or_insert(0) += 1;
    }

    Ok(output)
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ZeroWatermark {
    pub key: String,
    pub freq: usize,
    pub wm: String,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ZeroWatermarkRange {
    pub start: usize,
    pub end: usize,
}

impl ZeroWatermarkRange {
    pub fn len(&self) -> usize {
        if self.end < self.start {
            return 0
        }
        self.end - self.start
    }
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct ZeroWatermarkResult {
    pub key: String,
    pub matched_ranges: Vec<ZeroWatermarkRange>,
    pub unmatched_ranges: Vec<ZeroWatermarkRange>,
    pub matching_percent: usize,
    pub source_coverage: usize,
    pub source_wm: String,
}

// Implement the Zero-Watermarking Algorithm for the stream
pub fn zero_watermark_stream<R: Read + Seek>(
    reader: &mut R,
    min_keywords: usize,
) -> Result<Vec<ZeroWatermark>> {
    let mut output = Vec::new();
    let word_map = stream_histogram(reader)?;

    // get the list of lines in the reader stream and convert to a vector of words
    reader.rewind()?;
    let mut buf_reader = BufReader::new(reader);
    let mut reader_str = String::new();
    buf_reader.read_to_string(&mut reader_str)?;

    let words = reader_str.split_whitespace().collect::<Vec<&str>>();
    if words.len() < 2 {
        return Err(anyhow::anyhow!(
            "Not enough words to implement zero-watermarking"
        ));
    }

    // convert reader_str to a Vec of character
    let chars: Vec<char> = reader_str.clone().chars().collect();
    let chars_len = chars.len();

    // get sorted list of words by frequency
    let mut sorted_words: Vec<(String, usize)> = word_map.into_iter().collect();
    sorted_words.sort_by(|a, b| a.1.cmp(&b.1));
    sorted_words.reverse();

    // implement the zero-watermarking algorithm for most frequent word
    if words.len() > 2 {
        for (ordered_word, frequency) in &sorted_words {
            if *frequency < min_keywords {
                continue;
            }
            let mut watermark = String::new();
            let mut pos_dist = 0; // distance between markers
            let mut last_pos = 0;

            for i in 1..words.len() - 1 {
                let word_len = words[i - 1].len();
                pos_dist += word_len;

                while pos_dist < chars_len {
                    if chars[pos_dist].is_whitespace() {
                        pos_dist += 1;
                    } else {
                        break;
                    }
                }

                if words[i] == *ordered_word {
                    let offset = if watermark.is_empty() {
                        pos_dist
                    } else {
                        pos_dist - last_pos // distance from last instance
                    };

                    let before = words[i - 1].len();
                    let after = if i + 1 <= words.len() {
                        words[i + 1].len()
                    } else {
                        0
                    };

                    watermark.push_str(&format!("{}-{}-{}", offset, before, after));
                    if i < words.len() - 2 {
                        watermark.push_str(",");
                    }

                    last_pos = pos_dist
                }
            }

            output.push(ZeroWatermark {
                key: ordered_word.to_string(),
                freq: *frequency,
                wm: watermark,
            });
        }
    } else {
        return Err(anyhow::anyhow!(
            "Not enough words to implement zero-watermarking"
        ));
    }

    Ok(output)
}

pub fn compare_zero_watermark_stream<R: Read + Seek>(
    wm: &[ZeroWatermark],
    reader: &mut R,
) -> Result<Vec<ZeroWatermarkResult>> {
    let ewm = zero_watermark_stream(reader, 1)?;

    compare_zero_watermarks(wm, &ewm)
}

fn is_sub<T: PartialEq>(mut haystack: &[T], needle: &[T]) -> Option<usize> {
    if needle.len() == 0 {
        return None;
    }
    let mut pos = 0;
    while !haystack.is_empty() {
        if haystack.starts_with(needle) {
            return Some(pos);
        }
        haystack = &haystack[1..];
        pos += 1;
    }
    None
}

pub fn compare_zero_watermarks(
    wm: &[ZeroWatermark],
    ewm: &[ZeroWatermark],
) -> Result<Vec<ZeroWatermarkResult>> {
    let mut output = Vec::new();

   
        // determine distance checking arrays
        let mut wm_map = HashMap::new();
        let mut ewm_map = HashMap::new();

        for w in wm {
            let mut wm_vals = String::new();

            let key = w.key.to_owned();

            let mut offsets = Vec::new();

            for tuple in w.wm.clone().trim_end_matches(",").split(",") {
                let vals: Vec<&str> = tuple.split("-").collect();

                if vals.len() != 3 {
                    return Err(anyhow::anyhow!("watermark tuple incorrect"));
                }

                let tmp_token = format!("{}-{},", vals[1], vals[2]);

                offsets.push(vals[0].parse::<usize>()?);
                wm_vals.push_str(&tmp_token);
            }
            let trimmed = wm_vals.trim_end_matches(",");
            wm_map.insert(key, (offsets, trimmed.to_string()));
        }

        for w in ewm {
            let mut wm_vals = String::new();

            let key = w.key.to_owned();

            let mut offsets = Vec::new();

            for tuple in w.wm.trim_end_matches(",").split(",") {
                let vals: Vec<&str> = tuple.split("-").collect();

                if vals.len() != 3 {
                    return Err(anyhow::anyhow!("watermark tuple incorrect"));
                }

                let tmp_token = format!("{}-{},", vals[1], vals[2]);

                offsets.push(vals[0].parse::<usize>()?);
                wm_vals.push_str(&tmp_token);
            }
            let trimmed = wm_vals.trim_end_matches(",");
            ewm_map.insert(key, (offsets, trimmed.to_string()));
        }

        // try most frequent from test source
        for ewm_in in ewm {
            let key = &ewm_in.key;
            if let Some((positions, watermark)) = &ewm_map.get(&ewm_in.key) {
                // if key is present in reference
                if let Some((source_positions, source_watermark)) = wm_map.get(key) {
                    let source_wm = source_watermark;
                    let dest_wm = watermark;

                    let mut offsets = Vec::new();
                    let mut next_wm_start = positions[0];
                    offsets.push(next_wm_start); // add initial value
                    for pos in &positions[1..] {
                        if offsets.len() > 0 {
                            next_wm_start += *pos;
                            offsets.push(next_wm_start);
                        }
                    }

                    let word_matches = rkr_gst::run(dest_wm.as_bytes(), source_wm.as_bytes(), 6, 6);

                    let mut result = ZeroWatermarkResult {
                        key: key.clone(),
                        matched_ranges: Vec::new(),
                        matching_percent: 0,
                        unmatched_ranges: Vec::new(),
                        source_wm: source_watermark.clone(),
                        source_coverage: 0,
                    };

                    for m in &word_matches {
                        /*
                        println!("dest positions: {:?}\n", positions);
                        println!("source positions: {:?}\n", source_positions);
                        println!("dest watermarks: {:?}", dest_wm);
                        println!("source watermarks: {:?}", source_wm);

                        println!("key: {} - {:?}", key, word_matches);
                        */

                        let (range_unknown, range_match) = dest_wm
                            .split_at(m.pattern_index + m.length)
                            .0
                            .split_at(m.pattern_index);

                        let range_unknown =
                            range_unknown.trim_end_matches(",").trim_start_matches(",");
                        let range_match = range_match.trim_end_matches(",").trim_start_matches(",");

                        // if there is no unknown range then fall back to positional analysis
                        if range_unknown.is_empty() {
                            if let Some(match_pos) = is_sub(&source_positions[1..], &positions[1..]) {
                                let mut dest_len = positions[0];
                                for pos in &positions[1..] {
                                    dest_len += *pos;
                                }

                                let zmr = ZeroWatermarkRange {
                                    start: positions[0],
                                    end: dest_len,
                                };

                                // get additional source len
                                let mut additional = 0;
                                for delta in &source_positions[0..match_pos] {
                                    additional += *delta;
                                }
                                
                                for delta in &source_positions[(match_pos + positions.len())..] {
                                    additional += *delta;
                                }

                                result.matching_percent = 100;
                                result.source_coverage = ((zmr.len() as f32 / (additional as f32 + (zmr.len()) as f32)) * 100f32).ceil() as usize;
                                result.matched_ranges.push(zmr);
                            } else {
                                let mut tracking_pos = positions[0];
                                for i in 1..positions.len() {
                                    let start_pos = tracking_pos;
                                    tracking_pos += positions[i];

                                    if positions[i] != source_positions[i] {
                                        let diff = ZeroWatermarkRange {
                                            start: start_pos,
                                            end: tracking_pos,
                                        };
                                        result.unmatched_ranges.push(diff);
                                    }
                                    break; // just catch the first one
                                }
                                let mut ranges_with_change = 0;
                                for zwmr in &result.unmatched_ranges {
                                    ranges_with_change += (zwmr.end - zwmr.start);
                                }

                                result.matching_percent =
                                    (((tracking_pos as f32 - ranges_with_change as f32)
                                        / tracking_pos as f32)
                                        * 100f32)
                                        .ceil() as usize;
                            }
                        } else {
                            let range_unknown_offset_cnt = range_unknown.split(",").count();
                            let range_match_offset_cnt = range_match.split(",").count();
                            let remaining_offset_cnt = positions.len()
                                - (range_unknown_offset_cnt + range_match_offset_cnt);

                            if positions.len()
                                != range_unknown_offset_cnt
                                    + range_match_offset_cnt
                                    + remaining_offset_cnt
                            {
                                return Err(anyhow::anyhow!("bad offset count calculation"));
                            }

                            let mut curr_position = positions[0];
                            for i in 1..range_unknown_offset_cnt + 1 {
                                curr_position += positions[i];
                            }

                            // add the unknown range
                            let unmatched_end = curr_position - 1;
                            result.unmatched_ranges.push(ZeroWatermarkRange {
                                start: 0,
                                end: unmatched_end,
                            });
                            let unmatched_end = curr_position - 1;

                            let mut match_range = ZeroWatermarkRange {
                                start: curr_position,
                                end: 0,
                            };
                            for i in (range_unknown_offset_cnt + 2)
                                ..(range_unknown_offset_cnt + range_match_offset_cnt)
                            {
                                curr_position += positions[i];
                            }
                            match_range.end = curr_position;
                            result.matched_ranges.push(match_range);

                            result.matching_percent =
                                (((curr_position as f32 - unmatched_end as f32)
                                    / curr_position as f32)
                                    * 100f32)
                                    .ceil() as usize;
                        }
                    }
                    output.push(result);
                    //println!("key: {} - {:?}", key, word_matches);
                }
            }
        }

        Ok(output)
    
}
