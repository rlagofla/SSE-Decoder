#!/bin/bash

# 定义表头
HEADER_MY="BizIndex,Channel,SecurityID,TickTime,Type,BuyOrderNO,SellOrderNO,Price,Qty,TradeMoney,TickBSFlag,PMAP,OuterSeq,FrameIdx,RecIdx"

# 输入输出文件路径
INPUT_MY="out/all-day.csv"

SECURITY="601868"

OUTPUT_MY="0512-$SECURITY.csv"

# 写入表头（覆盖模式）

# 写入表头（覆盖模式）
echo "$HEADER_MY" > "$OUTPUT_MY"

# 追加匹配 ',2,601868,' 的数据行（注意双引号）
grep ",2,$SECURITY," "$INPUT_MY" >> "$OUTPUT_MY"