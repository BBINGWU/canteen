#!/bin/bash


for verilogfile in /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/scd/netlists/*.v
do
  scdfile=${verilogfile%.*}.scd
  /Users/bingwu/Downloads/毕业论文/code/zhubo/TinyGarble/build/scd/V2SCD_Main -i $verilogfile -o $scdfile --log2std &
done
wait
