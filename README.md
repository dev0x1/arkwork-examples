<h1 align="center">arkwork-rs library examples</h1>

## Overview

Few basic examples showing how to use [arkwork-rs libraries](https://github.com/arkworks-rs) to construct zk-SNARKS circuits. Examples use Groth16 and Marlin zk-SNARKs system.

Examples are:
* Prover claims that she knows "Two values *a* and *b* such that *a * b == c* where c is a public value".
* Prover claims that she knows "A x such that *x^3 + x + 5 == 35*". This example is based on [Christian Lundkvist's libsnark tutorial](https://github.com/christianlundkvist/libsnark-tutorial).
    * Implemented as arkworks circuit style, also as arkworks gadget style.
* Example demonstrating concept of universal SRS(setup parameters) in Marlin, here we use 2 circuits with same setup parameter.

## Build and Run
```sh
cargo build
cargo test
```

