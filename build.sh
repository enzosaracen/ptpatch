#!/bin/sh

cd stub
make
cd ../cli
cargo build --release
