//! This crate contains a very stripped down copy of the `test` crate.
//! `test` usually requires full `std` support, but we need to use it from a
//! `no_std` target.
//! The `test` crate is implicitly used by the `#[test]` attribute.
#![no_std]

#[derive(Clone, Copy)]
pub struct TestDescAndFn {
    pub testfn: StaticTestFn,
    pub desc: TestDesc,
}

#[derive(Clone, Copy)]
pub struct StaticTestFn(pub fn());

#[derive(Clone, Copy)]
pub struct TestDesc {
    pub name: StaticTestName,
    pub ignore: bool,
    pub ignore_message: Option<&'static str>,
    pub source_file: &'static str,
    pub start_line: usize,
    pub start_col: usize,
    pub end_line: usize,
    pub end_col: usize,
    pub should_panic: ShouldPanic,
    pub compile_fail: bool,
    pub no_run: bool,
    pub test_type: TestType,
}

#[derive(Clone, Copy)]
pub struct StaticTestName(pub &'static str);

#[derive(Clone, Copy)]
pub enum TestType {
    UnitTest,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum ShouldPanic {
    Yes,
    No,
}

pub fn assert_test_result(_: ()) {}
