//! Streaming redaction of secret values from a byte stream.
//!
//! Matches are found even when a value is split across reads: bytes that could be the start
//! of a secret are held back until enough input arrives to decide. Longer secrets win when
//! values overlap.

use std::io::{self, Read, Write};

pub struct Redactor {
    /// (value, replacement), longest value first.
    patterns: Vec<(Vec<u8>, Vec<u8>)>,
    pending: Vec<u8>,
}

enum Hit {
    Full(usize),
    /// The remaining input is a proper prefix of some pattern.
    Partial,
    None,
}

impl Redactor {
    pub fn new(secrets: &[(String, String)]) -> Redactor {
        let mut patterns: Vec<(Vec<u8>, Vec<u8>)> = secrets
            .iter()
            .filter(|(_, v)| !v.is_empty())
            .map(|(name, v)| {
                (
                    v.as_bytes().to_vec(),
                    format!("[REDACTED:{name}]").into_bytes(),
                )
            })
            .collect();
        patterns.sort_by_key(|p| std::cmp::Reverse(p.0.len()));
        Redactor {
            patterns,
            pending: Vec::new(),
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
        while i < buf.len() {
            match self.hit(&buf[i..], eof) {
                Hit::Full(p) => {
                    out.write_all(&buf[emitted..i])?;
                    out.write_all(&self.patterns[p].1)?;
                    i += self.patterns[p].0.len();
                    emitted = i;
                }
                Hit::Partial => break,
                Hit::None => i += 1,
            }
        }
        out.write_all(&buf[emitted..i])?;
        out.flush()?;
        self.pending = buf[i..].to_vec();
        Ok(())
    }

    /// Copies `input` to `out`, redacting as it goes.
    pub fn copy(mut self, mut input: impl Read, mut out: impl Write) -> io::Result<()> {
        let mut buf = [0u8; 8192];
        loop {
            match input.read(&mut buf) {
                Ok(0) => return self.finish(&mut out),
                Ok(n) => self.feed(&buf[..n], &mut out)?,
                Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn run(secrets: &[(&str, &str)], chunks: &[&[u8]]) -> String {
        let s: Vec<_> = secrets
            .iter()
            .map(|(a, b)| (a.to_string(), b.to_string()))
            .collect();
        let mut r = Redactor::new(&s);
        let mut out = Vec::new();
        for c in chunks {
            r.feed(c, &mut out).unwrap();
        }
        r.finish(&mut out).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn redacts_whole_and_split() {
        let s = [("TOK", "s3cr3t-value")];
        assert_eq!(run(&s, &[b"a s3cr3t-value b"]), "a [REDACTED:TOK] b");
        assert_eq!(
            run(&s, &[b"a s3c", b"r3t-va", b"lue b"]),
            "a [REDACTED:TOK] b"
        );
        let input = b"xx s3cr3t-value yy s3cr3t-value";
        let bytewise: Vec<&[u8]> = input.chunks(1).collect();
        assert_eq!(run(&s, &bytewise), "xx [REDACTED:TOK] yy [REDACTED:TOK]");
    }

    #[test]
    fn partial_prefix_at_eof_is_kept() {
        let s = [("TOK", "s3cr3t-value")];
        assert_eq!(run(&s, &[b"ends with s3cr"]), "ends with s3cr");
        assert_eq!(run(&s, &[b"s3cs3cr3t-value"]), "s3c[REDACTED:TOK]");
    }

    #[test]
    fn longest_wins_and_multiple() {
        let s = [("SHORT", "abc"), ("LONG", "abcdef"), ("OTHER", "zz")];
        assert_eq!(
            run(&s, &[b"abcdef abc zz"]),
            "[REDACTED:LONG] [REDACTED:SHORT] [REDACTED:OTHER]"
        );
        assert_eq!(run(&s, &[b"ab", b"cd", b"x"]), "[REDACTED:SHORT]dx");
    }

    #[test]
    fn empty_secret_ignored() {
        assert_eq!(run(&[("E", "")], &[b"hello"]), "hello");
    }
}
