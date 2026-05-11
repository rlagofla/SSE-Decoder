#!/bin/bash

# 定义表头
HEADER_MDL="BizIndex,Channel,SecurityID,TickTime,Type,BuyOrderNO,SellOrderNO,Price,Qty,TradeMoney,TickBSFlag,LocalTime,SeqNo"

# 输入输出文件路径
INPUT_MDL="data/0511/mdl_4_24_0.csv"

SECURITY="601868"

OUTPUT_MDL="data/0511/mdl424-$SECURITY.csv"

# 写入表头（覆盖模式）
echo "$HEADER_MDL" > "$OUTPUT_MDL"

# 追加匹配 ',2,601868,' 的数据行（注意双引号）
grep ",2,$SECURITY," "$INPUT_MDL" >> "$OUTPUT_MDL"