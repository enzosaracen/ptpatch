#!/bin/sh

cd stub
make
cd ../cmd
cargo build --release
