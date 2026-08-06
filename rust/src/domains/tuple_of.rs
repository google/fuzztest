// TODO(yamilmorales, tinmar, mathuxny-73): Replace generated wrapper domain (to deduplicate
// implementations for tests with the same number of parameters) with these, meaning we should
// `impl Domain` on these tuples.

pub type TupleOf1<T0> = (T0,);
pub type TupleOf2<T0, T1> = (T0, T1);
