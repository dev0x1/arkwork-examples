<h1 align="center">arkwork-rs library examples</h1>

## Overview

Few basic examples showing how to use [arkwork-rs libraries](https://github.com/arkworks-rs) to construct zk-SNARKS circuits.

Examples are:
* Prover claims that she knows "Two values *a* and *b* such that *a * b == c* where c is a public value".
* Prover claims that she knows "A x such that *x^3 + x + 5 == 35*". This example is based on [Christian Lundkvist's libsnark tutorial](https://github.com/christianlundkvist/libsnark-tutorial).

## Build and Run
```sh
cargo build
cargo test
```

