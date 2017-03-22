#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
#  des.py
#
#  Copyright 2017 SnDream <xnight@outlook.com>
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; either version 2 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program; if not, write to the Free Software
#  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#  MA 02110-1301, USA.
#
#

# 生成随机密钥时使用
import random

# 功能，有D（解密）和E（加密）可选
FUNC = {'D': 'Decrypt', 'E': 'Encrypt'}

# PC1表
# 用于秘钥的变换，变换过程中丢弃校验位
PC1_TABLE = [
    57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52,
    44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
# PC2表
# 用于将左右半值移位的结果进行重排，获得一次子密钥
PC2_TABLE = [
    14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13,
    2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]
# IP表
# 输入数据的重排
IP_TABLE = [
    58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24,
    16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
# FP表
# 输出结果的重排，FP=IP^(-1)
FP_TABLE = [
    40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21,
    61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]
# E表
# 将输入的32位半值扩充成48位
E_TABLE = [
    32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]
# P表
# 将S盒变换的结果进行重排
P_TABLE = [
    16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18,
    31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]
# 上述表中数据来自FIPS 46-3，数据最左为最低位，实际使用需要转换

# 秘钥调度次数表
# 代表每次生成子密钥前，左右半值移位的次数
TIME_TABLE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# SXY：S盒第X张表的第Y行
S10 = [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7]
S11 = [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8]
S12 = [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0]
S13 = [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
S20 = [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10]
S21 = [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5]
S22 = [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15]
S23 = [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
S30 = [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8]
S31 = [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1]
S32 = [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7]
S33 = [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
S40 = [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15]
S41 = [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9]
S42 = [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4]
S43 = [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
S50 = [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9]
S51 = [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6]
S52 = [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14]
S53 = [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
S60 = [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11]
S61 = [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8]
S62 = [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6]
S63 = [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
S70 = [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1]
S71 = [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6]
S72 = [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2]
S73 = [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
S80 = [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7]
S81 = [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2]
S82 = [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8]
S83 = [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]

# SX表，S盒第X张表
S1 = [S10, S11, S12, S13]
S2 = [S20, S21, S22, S23]
S3 = [S30, S31, S32, S33]
S4 = [S40, S41, S42, S43]
S5 = [S50, S51, S52, S53]
S6 = [S60, S61, S62, S63]
S7 = [S70, S71, S72, S73]
S8 = [S80, S81, S82, S83]

# S表
# 进行S盒变换用表，DES中最重要的加密步骤，进行非线性加密
S_TABLE = [S1, S2, S3, S4, S5, S6, S7, S8]
# 用查表代替计算移位次数
S_SHIFT = [42, 36, 30, 24, 18, 12, 6, 0]


def main(args):
# 主程序，通过命令行执行时附加参数作为输入
# 输入：加密/解密 明/密文(64位) 秘钥(64位,可选)
# 输出：输入参数及其结果
# 当秘钥不存在时自动生成一个密钥，输入和生成的密钥中，都有校验位，但不进行检查
    try:
        func = FUNC[args[1][0].upper()]
        iptvalue = (int(args[2], 16)) & 0xFFFFFFFFFFFFFFFF
    except Exception as e:
        print('Usage: des.py d|e Data [Key]')
        print('Error:', e)
        exit(1)
    try:
        keyvalue = (int(args[3], 16)) & 0xFFFFFFFFFFFFFFFF
    except Exception as e:
        keyvalue = random.randint(0, 0xFFFFFFFFFFFFFFFF)
    finally:
        keyvalue = checksumfix(keyvalue)
    if func is 'Decrypt':
        result = decrypt(iptvalue, keyvalue)
    elif func is 'Encrypt':
        result = encrypt(iptvalue, keyvalue)
    print(func, hex(iptvalue))
    print('Key    ', hex(keyvalue))
    print('Result ', hex(result))
    return 0


def decrypt(cipvalue, keyvalue):
# 解密
# 输入：密文(64位) 秘钥(64位)
# 输出：明文(64位)
    left, right = splitvalue(permutate(cipvalue, IP_TABLE, 64), 32)
    for subkey in getsubkeys(keyvalue)[::-1]:
        left, right = right, left ^ feistel(right, subkey)
    return permutate(mergevalue(right, left, 32), FP_TABLE, 64)


def encrypt(plavalue, keyvalue):
# 加密
# 输入：明文(64位) 秘钥(64位)
# 输出：密文(64位)
    left, right = splitvalue(permutate(plavalue, IP_TABLE, 64), 32)
    for subkey in getsubkeys(keyvalue):
        left, right = right, left ^ feistel(right, subkey)
    return permutate(mergevalue(right, left, 32), FP_TABLE, 64)


def getsubkeys(keyvalue):
# 获取子密钥
# 输入：秘钥(64位)
# 输出：子密钥(48位)*16
    left, right = splitvalue(permutate(keyvalue, PC1_TABLE, 64), 28)
    subkeys = []
    for times in TIME_TABLE:
        left, right = rol(left, times, 28), rol(right, times, 28)
        subkeys.append(permutate(mergevalue(left, right, 28), PC2_TABLE, 56))
    return subkeys


def feistel(halfblock, subkey):
# Feistel函数
# 输入：加密半值(32位) 子密钥(48位)
# 输出：加密结果(32位)
    expansion = permutate(halfblock, E_TABLE, 32)
    expansion ^= subkey
    result = 0
    for i in range(0, 8):
        xyyyyx = (expansion >> S_SHIFT[i]) & 0b111111
        xx = ((xyyyyx >> 4) & 0b10) | (xyyyyx & 1)
        yyyy = (xyyyyx >> 1) & 0b1111
        result = (result << 4) | S_TABLE[i][xx][yyyy]
    return permutate(result, P_TABLE, 32)


def permutate(value, table, length):
# 数据查表重排
# 输入：原值 所查重排表 原值长度
# 输出：重排结果
# 因为FIPS 46-3数据与实际有差异，需要进行转换计算，转换过程中需要用到原值长度
    result = 0
    for bit in table:
        result = (result << 1) | getbit(value, length - bit)
    return result


def rol(value, times, length):
# 简单循环左移
# 输入：原值 左移次数 原值长度
# 输出：左移结果
    return ((value << times) | (value >> (length - times))) & ((1 << length) - 1)


def mergevalue(left, right, length):
# 合并两个数
# 输入：左半值 右半值 半值长度
# 输出：左右合并值
    return (left << length) | (right)


def splitvalue(value, length):
# 拆分两个数
# 输入：左右合并值 半值长度
# 输出：左半值 右半值
    left = value >> length
    right = value & ((1 << length) - 1)
    return left, right


def getbit(value, bit):
# 获取value中的第bit位
# 输入：获取bit来源 获取位数
# 输出：对应位
# bit从0算起，最右为最低位
    return bool((value >> (bit)) & 1)


def checksumfix(value):
# 对秘钥校验位的修正
# 输入：原始密钥
# 输出：校验位正确的密钥
# 其实校验位根本没参与秘钥生成，大概是多此一举了
    result = 0
    csbit = 1
    for i in range(0, 64)[::-1]:
        if i & 0b111:
            bit = (value >> i) & 1
            result = (result << 1) | bit
            csbit ^= bit
        else:
            result = (result << 1) | csbit
            csbit = 1
    return result


if __name__ == '__main__':
    import sys
    sys.exit(main(sys.argv))
