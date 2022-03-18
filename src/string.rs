use core::fmt;

pub struct FixedString<const T : usize> {
	len : usize,
	data : [char; T],
}

impl<const T : usize> FixedString<T> {
	pub const fn new() -> Self {
		FixedString {
			len  : 0,
			data : ['\0'; T],
		}
	}

	pub fn from(str : &str) -> Self {
		let mut fs = FixedString::new();
		for (i, c) in str.chars().enumerate() {
			if i == T {
				break;
			}
			fs.data[i] = c;
			fs.len += 1;
		}
		fs
	}

	pub fn push(&mut self, c : char) {
		let l = self.len;

		if l > 0 && self.data[l - 1] == '\0' {
			return;
		}

		self.data[l] = c;
		self.len += 1;
	}

	pub fn equal_str(&self, s : &str) -> bool {
		for (i, c) in s.chars().enumerate() {
			if i >= T { return false; }
			if self.data[i] != c { return false; }
		}
		true
	}
}

impl<const T : usize> fmt::Display for FixedString<T> {
	fn fmt(&self, f : &mut fmt::Formatter) -> fmt::Result {
		let mut i = 0;
		while i < self.len {
			if let Err(e) = write!(f, "{}", self.data[i]) {
				return Err(e);
			}
			i += 1;
		}
		Ok(())
	}
}
