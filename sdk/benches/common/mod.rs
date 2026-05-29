pub const SIZES: &[Size] = &[Size::Small, Size::Medium, Size::Large];

#[derive(Clone, Copy)]
pub enum Size {
    Small,
    Medium,
    Large,
}

impl Size {
    pub fn as_str(self) -> &'static str {
        match self {
            Size::Small => "small",
            Size::Medium => "medium",
            Size::Large => "large",
        }
    }

    pub fn sample_size(self) -> usize {
        match self {
            Size::Small => 50,
            Size::Medium => 20,
            Size::Large => 10,
        }
    }
}
