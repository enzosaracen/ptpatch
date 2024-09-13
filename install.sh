#!/bin/sh

cd stub
make
cd ../cli
cargo install --path .
