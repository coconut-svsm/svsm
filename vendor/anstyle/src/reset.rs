/// Reset terminal formatting
#[derive(Copy, Clone, Default, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Reset;

impl Reset {
    /// Render the ANSI code
    ///
    /// `Reset` also implements `Display` directly, so calling this method is optional.
    #[inline]
    pub fn render(self) -> impl core::fmt::Display + Copy + Clone {
        self
    }
}

impl core::fmt::Display for Reset {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        RESET.fmt(f)
    }
}

pub(crate) const RESET: &str = "\x1B[0m";

#[test]
fn print_size_of() {
    use std::mem::size_of;
    dbg!(size_of::<Reset>());
}
