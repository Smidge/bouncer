//! Streaming redaction of secret values from a byte stream.
//!
//! Matches are found even when a value is split across reads: bytes that could be the start
//! of a secret are held back until enough input arrives to decide. Overlapping or chained
//! matches are merged, and the whole union is replaced by one marker, so no fragment of a
//! secret survives between two markers.
//!
//! The marker is `[REDACTED:<n>]`, where n is the 1-based position of the secret on the
//! command line. It never contains a secret's name, which could itself equal a value. If any
//! value occurs inside a marker string (for example a one-character value such as `1`), the
//! matched bytes are removed without a marker instead.

use std::io::{self, Read, Write};

use zeroize::{Zeroize, Zeroizing};

pub struct Redactor {
    /// (value, marker), longest value first.
    patterns: Vec<(Zeroizing<Vec<u8>>, Vec<u8>)>,
    pending: Zeroizing<Vec<u8>>,
}

enum Hit {
    Full(usize),
    /// The remaining input is a proper prefix of some pattern.
    Partial,
    None,
}

impl Redactor {
    /// `values[i]` is reported as `[REDACTED:i+1]`.
    pub fn new(values: &[&str]) -> Redactor {
        let mut patterns: Vec<(Zeroizing<Vec<u8>>, Vec<u8>)> = values
            .iter()
            .enumerate()
            .filter(|(_, v)| !v.is_empty())
            .map(|(i, v)| {
                (
                    Zeroizing::new(v.as_bytes().to_vec()),
                    format!("[REDACTED:{}]", i + 1).into_bytes(),
                )
            })
            .collect();
        let unsafe_marker = patterns.iter().any(|(v, _)| {
            patterns
                .iter()
                .any(|(_, m)| m.windows(v.len()).any(|w| w == &v[..]))
        });
        if unsafe_marker {
            for p in &mut patterns {
                p.1.clear();
            }
        }
        patterns.sort_by_key(|p| std::cmp::Reverse(p.0.len()));
        Redactor {
            patterns,
            pending: Zeroizing::new(Vec::new()),
        }
    }

    fn hit(&self, at: &[u8], eof: bool) -> Hit {
        for (i, (p, _)) in self.patterns.iter().enumerate() {
            if at.len() >= p.len() {
                if at.starts_with(p) {
                    return Hit::Full(i);
                }
            } else if !eof && p.starts_with(at) {
                return Hit::Partial;
            }
        }
        Hit::None
    }

    /// Processes `data` and writes everything that can be decided to `out`.
    pub fn feed(&mut self, data: &[u8], out: &mut impl Write) -> io::Result<()> {
        self.pending.extend_from_slice(data);
        self.drain(false, out)
    }

    /// Flushes held-back bytes at end of input.
    pub fn finish(&mut self, out: &mut impl Write) -> io::Result<()> {
        self.drain(true, out)
    }

    fn drain(&mut self, eof: bool, out: &mut impl Write) -> io::Result<()> {
        let buf = std::mem::take(&mut self.pending);
        let (mut i, mut emitted) = (0, 0);
        'scan: while i < buf.len() {
            match self.hit(&buf[i..], eof) {
                Hit::Full(p) => {
                    // Grow the region while any match starting inside it reaches further.
                    let mut end = i + self.patterns[p].0.len();
                    let mut j = i + 1;
                    while j < end {
                        match self.hit(&buf[j..], eof) {
                            Hit::Full(q) => end = end.max(j + self.patterns[q].0.len()),
                            Hit::Partial => break 'scan, // need more input to decide
                            Hit::None => {}
                        }
                        j += 1;
                    }
                    out.write_all(&buf[emitted..i])?;
                    out.write_all(&self.patterns[p].1)?;
                    i = end;
                    emitted = end;
                }
                Hit::Partial => break,
                Hit::None => i += 1,
            }
        }
        out.write_all(&buf[emitted..i])?;
        out.flush()?;
        self.pending = Zeroizing::new(buf[i..].to_vec());
        Ok(())
    }

    /// Copies `input` to `out`, redacting as it goes.
    pub fn copy(mut self, mut input: impl Read, mut out: impl Write) -> io::Result<()> {
        let mut buf = [0u8; 8192];
        let r = loop {
            match input.read(&mut buf) {
                Ok(0) => break self.finish(&mut out),
                Ok(n) => {
                    if let Err(e) = self.feed(&buf[..n], &mut out) {
                        break Err(e);
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => break Err(e),
            }
        };
        buf.zeroize();
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(values: &[&str], chunks: &[&[u8]]) -> String {
        let mut r = Redactor::new(values);
        let mut out = Vec::new();
        for c in chunks {
            r.feed(c, &mut out).unwrap();
        }
        r.finish(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn redacts_whole_and_split() {
        let s = ["s3cr3t-value"];
        assert_eq!(run(&s, &[b"a s3cr3t-value b"]), "a [REDACTED:1] b");
        assert_eq!(
            run(&s, &[b"a s3c", b"r3t-va", b"lue b"]),
            "a [REDACTED:1] b"
        );
        let input = b"xx s3cr3t-value yy s3cr3t-value";
        let bytewise: Vec<&[u8]> = input.chunks(1).collect();
        assert_eq!(run(&s, &bytewise), "xx [REDACTED:1] yy [REDACTED:1]");
    }

    #[test]
    fn partial_prefix_at_eof_is_kept() {
        let s = ["s3cr3t-value"];
        assert_eq!(run(&s, &[b"ends with s3cr"]), "ends with s3cr");
        assert_eq!(run(&s, &[b"s3cs3cr3t-value"]), "s3c[REDACTED:1]");
    }

    #[test]
    fn longest_wins_and_multiple() {
        let s = ["abc", "abcdef", "zz"];
        assert_eq!(
            run(&s, &[b"abcdef abc zz"]),
            "[REDACTED:2] [REDACTED:1] [REDACTED:3]"
        );
        assert_eq!(run(&s, &[b"ab", b"cd", b"x"]), "[REDACTED:1]dx");
    }

    #[test]
    fn overlaps_are_merged() {
        // "abcd" overlaps "cdef": no fragment of either may survive.
        let s = ["abcd", "cdef"];
        assert_eq!(run(&s, &[b"xabcdefx"]), "x[REDACTED:1]x");
        let bytewise: Vec<&[u8]> = b"xabcdefx".chunks(1).collect();
        assert_eq!(run(&s, &bytewise), "x[REDACTED:1]x");
        // Chains of overlaps.
        let s = ["aaab", "abbb", "bbbc"];
        assert_eq!(run(&s, &[b"-aaabbbc-"]), "-[REDACTED:1]-");
    }

    #[test]
    fn markers_never_reintroduce_values() {
        // A value that appears inside the marker text: drop matches without a marker.
        let out = run(&["RED", "long-secret"], &[b"a RED b long-secret c"]);
        assert_eq!(out, "a  b  c");
        let out = run(&["1"], &[b"x1y"]);
        assert_eq!(out, "xy");
    }

    #[test]
    fn empty_secret_ignored() {
        assert_eq!(run(&[""], &[b"hello"]), "hello");
    }
}
