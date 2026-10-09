//! Bounded JSONL tail reading: one read from the stored offset is split into complete lines and
//! what follows the last newline, without ever holding more than one read's bytes.

/// What follows the last complete line of one read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Remainder {
    /// The read ended on a newline (or held nothing).
    None,
    /// An unterminated line at the end of the file: kept uncounted until its newline arrives.
    Pending,
    /// The read stopped before the end of the file: the line is read again from its start.
    Unread,
    /// The whole read is one unterminated line of at least the line bound: it is discarded.
    Oversize,
}

/// One read from a stored offset, split.
#[derive(Debug, Eq, PartialEq)]
pub struct Split<'a> {
    /// Bytes skipped first while finishing a discarded line, its newline included.
    pub skipped: usize,
    /// Complete lines, each ending in a newline.
    pub complete: &'a [u8],
    pub remainder: Remainder,
    /// Bytes behind the new cursor: skipped, complete, and an oversize remainder.
    pub consumed: usize,
    /// A discarded line is still unfinished after this read.
    pub discarding: bool,
}

impl Split<'_> {
    /// The complete lines, newlines removed.
    pub fn lines(&self) -> impl Iterator<Item = &[u8]> {
        self.complete
            .split(|byte| *byte == b'\n')
            .take(self.complete.iter().filter(|byte| **byte == b'\n').count())
    }
}

/// Splits `bytes`, read from the stored offset. `discarding` continues a discarded line;
/// `at_end` says the read reached the end of the file it opened; `full` says it returned the
/// whole line bound.
pub fn split(bytes: &[u8], discarding: bool, at_end: bool, full: bool) -> Split<'_> {
    let skipped = if discarding {
        match bytes.iter().position(|byte| *byte == b'\n') {
            Some(index) => index + 1,
            None => {
                return Split {
                    skipped: bytes.len(),
                    complete: &[],
                    remainder: Remainder::None,
                    consumed: bytes.len(),
                    discarding: true,
                };
            }
        }
    } else {
        0
    };
    let body = &bytes[skipped..];
    let complete_len = body
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map_or(0, |index| index + 1);
    let rest = body.len() - complete_len;
    let remainder = if rest == 0 {
        Remainder::None
    } else if at_end {
        Remainder::Pending
    } else if full && skipped == 0 && complete_len == 0 {
        Remainder::Oversize
    } else {
        Remainder::Unread
    };
    let oversize = remainder == Remainder::Oversize;
    Split {
        skipped,
        complete: &body[..complete_len],
        remainder,
        consumed: skipped + complete_len + if oversize { rest } else { 0 },
        discarding: oversize,
    }
}

/// FNV-1a 64 of `bytes`: the stored first-line witness.
pub fn fnv1a64(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

#[cfg(test)]
mod tests {
    use super::{Remainder, split};

    #[test]
    fn split_keeps_pending_unread_and_oversize_apart() {
        let pending = split(b"a\nbc", false, true, false);
        assert_eq!(
            (pending.complete, pending.remainder, pending.consumed),
            (&b"a\n"[..], Remainder::Pending, 2)
        );
        assert_eq!(pending.lines().collect::<Vec<_>>(), vec![&b"a"[..]]);
        let unread = split(b"a\nbc", false, false, true);
        assert_eq!((unread.remainder, unread.consumed), (Remainder::Unread, 2));
        let oversize = split(b"abcd", false, false, true);
        assert_eq!(
            (oversize.remainder, oversize.consumed, oversize.discarding),
            (Remainder::Oversize, 4, true)
        );
        let finishing = split(b"xx\nab\n", true, true, false);
        assert_eq!(
            (finishing.skipped, finishing.complete, finishing.discarding),
            (3, &b"ab\n"[..], false)
        );
        let still = split(b"xxxx", true, true, false);
        assert_eq!(
            (still.consumed, still.discarding, still.remainder),
            (4, true, Remainder::None)
        );
    }
}
