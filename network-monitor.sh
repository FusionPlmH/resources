#!/bin/bash

# 檢查是否提供了網卡名稱
if [ "$#" -ne 1 ]; then
    echo "用法: $0 <網卡名稱>"
    exit 1
fi

INTERFACE=$1

# 初始化變數
PREV_RX_BYTES=0
PREV_TX_BYTES=0

# 每秒更新一次
while true; do
    # 獲取目前接收和傳送的位元組數
    RX_BYTES=$(cat /sys/class/net/$INTERFACE/statistics/rx_bytes)
    TX_BYTES=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes)

    # 計算目前的流量變化
    let "RX_DIFF=RX_BYTES-PREV_RX_BYTES"
    let "TX_DIFF=TX_BYTES-PREV_TX_BYTES"
    
    # 計算網速（位元組數轉換成 Gbps）
    RX_SPEED=$(echo "scale=2; ($RX_DIFF * 8) / (1024 * 1024)" | bc) # 8位元組轉位元
    TX_SPEED=$(echo "scale=2; ($TX_DIFF * 8) / (1024 * 1024)" | bc)

    # 輸出結果
    echo "接收流量: $RX_BYTES 位元組, 當前速度: ${RX_SPEED} Gbps"
    echo "傳送流量: $TX_BYTES 位元組, 當前速度: ${TX_SPEED} Gbps"
    echo ""

    # 更新前一次的位元組數
    PREV_RX_BYTES=$RX_BYTES
    PREV_TX_BYTES=$TX_BYTES

    # 每隔 1 秒刷新
    sleep 1
done
