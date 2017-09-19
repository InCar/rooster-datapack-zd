package com.incarcloud.rooster.util;

import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;

/**
 * zd d2s DataPack工具类
 * User: chenz
 * Date: 2017/9/5
 * Time: 11:57
 */
public class D2sDataPackUtil extends DataPackUtil {
    /**
     * 获取协议命令标识
     *
     * @param buffer
     * @return
     */
    public static Integer getCmdId(byte[] buffer) {
        int id = buffer[0] & 0xFF;
        id = id << 8;
        id = id | (buffer[1] & 0xFF);
        id = id << 8;
        id = id | (buffer[2] & 0xFF);
        return id;
    }

    /**
     * 打印调试信息，调试完成后设置false
     *
     * @param string 字符串
     */
    public static void debug(String string) {
        if (true) {
            System.out.println(string);
        }
    }

    /**
     * 从给定的数组缓存中获取片断；
     *
     * @param data
     * @param fromIdx
     * @param toIdx
     * @return
     */
    public static byte[] getRange(byte[] data, int fromIdx, int toIdx) {

        if (data == null || fromIdx > toIdx || toIdx > data.length) {
            throw new IllegalArgumentException("arguments is invalid");
        }
        byte[] range = new byte[toIdx - fromIdx];
        System.arraycopy(data, fromIdx, range, 0, toIdx - fromIdx);
        return range;
    }

    /**
     * 从给定的数组缓存中获取整数值；遵循大端模式
     *
     * @param data
     * @param fromIdx
     * @param toIdx
     * @return
     */
    public static int getInt4Bigendian(byte[] data, int fromIdx, int toIdx) {

        if (data == null || fromIdx > toIdx || toIdx > data.length) {
            throw new IllegalArgumentException("arguments is invalid");
        }
        if (toIdx - fromIdx > 4) {
            throw new IllegalArgumentException("arguments is invalid");
        }
        int intVal = 0x0;
        // 判断是否是负数
        boolean isNegative = ((data[fromIdx] & 0x80) == 0x80);

        // 负数采用补码算法
        if (isNegative) {
            for (int i = fromIdx; i < toIdx && i < fromIdx + 4; i++) {
                intVal ^= (~data[i] & 0xFF) << (8 * (toIdx - 1 - i));
            }
            intVal = (intVal + 1) * -1;
        }

        // 正数直接返回原码
        else {
            for (int i = fromIdx; i < toIdx && i < fromIdx + 4; i++) {
                intVal ^= (data[i] & 0xFF) << (8 * (toIdx - 1 - i));
            }
        }
        return intVal;
    }

    /**
     * @param buffer byte[]{year-2000,month,day_of_month,hour_of_day,minute,seconds}
     * @param offset
     * @return
     * @etc byte[]{16, 1, 12, 3, 3, 1} --> Date("2016-01-12 03:03:01")
     */
    public static long buf2Date(byte[] buffer, int offset) throws Exception {
        if (buffer.length - offset < 6) {
            throw new Exception("buffer length is not enough");
        }
        Calendar now = Calendar.getInstance();
        now.set(Calendar.YEAR, (buffer[offset + 0] & 0xFF) + 2000);
        now.set(Calendar.MONTH, (buffer[offset + 1] & 0xFF) - 1);
        now.set(Calendar.DAY_OF_MONTH, (buffer[offset + 2] & 0xFF));
        now.set(Calendar.HOUR_OF_DAY, (buffer[offset + 3] & 0xFF));
        now.set(Calendar.MINUTE, (buffer[offset + 4] & 0xFF));
        now.set(Calendar.SECOND, (buffer[offset + 5] & 0xFF));
        now.set(Calendar.MILLISECOND, 0);
        return now.getTimeInMillis();
    }

    /**
     * @param times
     * @return byte[]{year-2000,month,day_of_month,hour_of_day,minute,seconds}
     * @example 2016-01-12 03-03-01 --> byte[]{16, 1, 12, 3, 3, 1}
     */
    public static byte[] date2buf(long times) {
        byte[] packetBuffer = new byte[6];
        Calendar now = Calendar.getInstance();
        now.setTimeInMillis(times);
        packetBuffer[0] = (byte) (now.get(Calendar.YEAR) - 2000);
        packetBuffer[1] = (byte) (now.get(Calendar.MONTH) + 1);
        packetBuffer[2] = (byte) now.get(Calendar.DAY_OF_MONTH);
        packetBuffer[3] = (byte) now.get(Calendar.HOUR_OF_DAY);
        packetBuffer[4] = (byte) now.get(Calendar.MINUTE);
        packetBuffer[5] = (byte) now.get(Calendar.SECOND);
        return packetBuffer;
    }

    /**
     * 装包-异或校验
     *
     * @param buffer
     * @return
     */
    public static byte[] addCheck(byte[] buffer) {
        if (buffer[0] == (byte) 0x23 && buffer[1] == (byte) 0x23) {
            //添加数据单元长度
            int length = buffer.length - 25;
            buffer[22] = (byte) ((length >>> 8) & 0xFF);
            buffer[23] = (byte) (length & 0xFF);
            //添加校验码
            int crc = buffer[2] & 0xFF;
            for (int i = 3; i < buffer.length - 1; i++) {
                crc = crc ^ (buffer[i] & 0xFF);
            }
            buffer[buffer.length - 1] = (byte) (crc & 0xFF);
            return buffer;
        }
        return null;
    }

    /**
     * 将指定范围的buffer转换为Ascii字符串
     *
     * @param buffer
     * @param frmIndex
     * @param toIndex
     * @return
     */
    public static String getAsciiString(byte[] buffer, int frmIndex, int toIndex) {
        StringBuffer sbu = new StringBuffer();

        for (int i = frmIndex; i < toIndex; ++i) {
            sbu.append((char) (buffer[i] & 255));
        }
        return sbu.toString();
    }

    /**
     * 将byte数组转换为整数，大端模式
     *
     * @param buffer
     * @return
     */
    public static long toLong(byte[] buffer) {
        long bit64 = 0;
        bit64 |= (buffer[7] & 0xFF);
        bit64 = (bit64 << 8);
        bit64 |= (buffer[6] & 0xFF);
        bit64 = (bit64 << 8);
        bit64 |= (buffer[5] & 0xFF);
        bit64 = (bit64 << 8);
        bit64 |= (buffer[4] & 0xFF);
        bit64 = (bit64 << 8);
        bit64 |= (buffer[3] & 0xFF);
        bit64 = (bit64 << 8);
        bit64 |= (buffer[2] & 0xFF);
        bit64 = (bit64 << 8);
        bit64 |= (buffer[1] & 0xFF);
        bit64 = (bit64 << 8);
        bit64 |= (buffer[0] & 0xFF);
        return bit64;
    }

    /**
     * 获得WORD的字节码列表信息(2个字节)
     *
     * @param integer 数值
     * @return
     */
    public static List<Byte> getWordByteList(int integer) {
        byte[] bytes = getIntegerBytes(integer, 2);
        List<Byte> byteList = new ArrayList<>();
        for (int i = 0; i < bytes.length; i++) {
            byteList.add(bytes[i]);
        }
        return byteList;
    }

    /**
     * 获得整型数值的字节码信息(1个字节)
     *
     * @param integer　数值
     * @return
     */
    public static byte getIntegerByte(int integer) {
        return (byte) integer;
    }

    protected D2sDataPackUtil() {
        super();
    }
}
