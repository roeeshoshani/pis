macro_rules! array_vec {
    [$($x:expr),*] => ({
        // allow an unused mut variable, since if the sequence is empty, the vec will never be mutated.
        #[allow(unused_mut)] {
            let mut vec = $crate::ArrayVec::new();
            $(vec.push($x);)*
            vec
        }
    });
}

pub(crate) use array_vec;
