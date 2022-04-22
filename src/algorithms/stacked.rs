use crate::{
    cyphers::{PadCypher, UnpadCypher},
    datastructs::ProvidesPad,
};

pub enum Algorithm<T> {
    Padding(Box<dyn PadCypher<T>>),
    Unpadding(Box<dyn UnpadCypher<T>>),
}

pub struct StackedCypher<T> {
    algorithms: Vec<Algorithm<T>>,
}

impl<T: Clone + ProvidesPad> StackedCypher<T> {
    pub fn new(algorithms: Vec<Algorithm<T>>) -> Self {
        StackedCypher { algorithms }
    }

    pub fn push_padding<C: PadCypher<T> + 'static>(&mut self, cypher: C) {
        self.algorithms.push(Algorithm::Padding(Box::new(cypher)));
    }

    pub fn push_unpadding<C: UnpadCypher<T> + 'static>(&mut self, cypher: C) {
        self.algorithms.push(Algorithm::Unpadding(Box::new(cypher)));
    }

    pub fn encrypt(&self, data: &[T]) -> (Vec<usize>, Vec<T>) {
        self.algorithms
            .iter()
            .fold((vec![], data.to_vec()), |(mut indices, data), op| {
                let (created_indices, data) = match op {
                    Algorithm::Padding(op) => op.encrypt_with_pad(&data),
                    Algorithm::Unpadding(op) => (data.len(), op.encrypt_unpad(&data)),
                };

                indices.push(created_indices);
                (indices, data)
            })
    }

    pub fn decrypt(&self, data: &[T], sizes: &[usize]) -> Vec<T> {
        self.algorithms
            .iter()
            .zip(sizes.iter())
            .rev()
            .fold(data.to_vec(), |data, (op, &size)| match op {
                Algorithm::Padding(op) => op.decrypt_with_pad(&data, size),
                Algorithm::Unpadding(op) => op.decrypt_unpad(&data),
            })
    }

    pub(crate) fn len(&self) -> usize {
        self.algorithms.len()
    }

    pub(crate) fn items(&self) -> impl Iterator<Item = &Algorithm<T>> {
        self.algorithms.iter()
    }
}
