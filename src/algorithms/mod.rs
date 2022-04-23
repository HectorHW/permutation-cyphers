#![allow(dead_code)]
pub mod decode;
pub mod permutation;
pub mod rail_fence;
pub mod serialization;
pub mod stacked;
pub mod vertical;

///accepts `indices` which are used as follows:
///
///for item and target index `i`: result\[i\] = item
pub(super) fn move_by_indices<T>(data: Vec<T>, indices: &[usize]) -> Vec<T> {
    use std::mem::MaybeUninit;
    assert_eq!(indices.len(), data.len());
    let mut items: Vec<MaybeUninit<T>> = std::iter::repeat_with(|| MaybeUninit::uninit())
        .take(data.len())
        .collect();

    for (&index, value) in indices.iter().zip(data.into_iter()) {
        items[index].write(value);
    }

    items
        .into_iter()
        //this is safe because all indices are present in permutation
        // => all indices are written exactly once
        .map(|item| unsafe { item.assume_init() })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::move_by_indices;

    #[test]
    fn substitution() {
        assert_eq!(
            move_by_indices(vec!['a', 'b', 'c', 'd'], &[1, 2, 0, 3]),
            vec!['c', 'a', 'b', 'd']
        )
    }
}
