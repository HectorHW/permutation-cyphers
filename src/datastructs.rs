#[derive(Copy, Clone, Debug, Default)]
pub struct Bit(bool);

pub trait ProvidesPad: Sized {
    fn get_pad(pad_size: usize) -> Vec<Self>;
}

impl<T> ProvidesPad for T
where
    T: Default,
{
    fn get_pad(size: usize) -> Vec<Self> {
        std::iter::repeat_with(|| T::default()).take(size).collect()
    }
}
