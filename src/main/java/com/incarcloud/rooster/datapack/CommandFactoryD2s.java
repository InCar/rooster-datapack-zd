package com.incarcloud.rooster.datapack;

import com.incarcloud.rooster.gather.cmd.CommandFacotryManager;
import com.incarcloud.rooster.gather.cmd.CommandFactory;
import com.incarcloud.rooster.gather.cmd.CommandType;
import com.incarcloud.rooster.util.D2sDataPackUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;

import java.util.ArrayList;
import java.util.List;

/**
 * Created with IntelliJ IDEA.
 * User: chenz
 * Date: 2017/9/5 0005
 * Time: 11:01
 */
public class CommandFactoryD2s implements CommandFactory {
    static {
        /**
         * 声明数据包版本与解析器类关系
         */
        CommandFacotryManager.registerCommandFacotry(DataParserD2s.PROTOCOL_PREFIX + DataParserD2s.PROTOCOL_VERSION, CommandFactoryD2s.class);
    }

    @Override
    public ByteBuf createCommand(CommandType type, Object... args) throws Exception {
        // 基本验证，必须有参数，第一个为终端手机号，即设备号
        if (null == args && 0 < args.length) {
            throw new IllegalArgumentException("args is null");
        }
        // 初始化List容器，装载【消息头+消息体】
        List<Byte> byteList = new ArrayList<>();
        //头部信息6
        byteList.add((byte) 0x23);
        byteList.add((byte) 0x23);
        // 预留回复命令字位置-命令标识
        byteList.add((byte) 0xFF);
        //预留回复命令字位置-应答标识
        byteList.add((byte) 0xFF);
        //设置deviceCode(iccid)
        String deviceCode = (String) args[0];
        byte[] deviceCodeArr = deviceCode.getBytes();

        /**
         * deviceCode不足17位，抛出异常。
         */
        if (deviceCodeArr.length < 17) {
            throw new IllegalArgumentException("device code少于17位!");
        }

        for (int i = 0; i < deviceCodeArr.length; i++) {
            byteList.add(deviceCodeArr[i]);
        }
        //数据加密方式
        byteList.add((byte) 0);
        //数据单元长度
        byteList.add((byte) 0);
        byteList.add((byte) 0);
        //添加时间
        byte[] time = D2sDataPackUtil.date2buf(System.currentTimeMillis());
        for (int i = 0; i < time.length; i++) {
            byteList.add(time[i]);
        }
        //添加流水号
        byteList.add((byte) 0x00);
        byteList.add((byte) 0x00);


        // 根据type生成控制指令
        switch (type) {
            case OPEN_DOOR: //打开车门
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x01);
                //添加指令参数长度
                byteList.add((byte) 0x01);
                //添加控制指令参数-开锁
                byteList.add((byte) 0x01);

                break;
            case CLOSE_DOOR: //关闭车门
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x01);
                //添加指令参数长度
                byteList.add((byte) 0x01);
                //添加控制指令参数-落锁
                byteList.add((byte) 0x02);

                break;
            case BACK_DOOR_UNLOCK: //远程后备箱解锁
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x02);
                //添加指令参数长度
                byteList.add((byte) 0x01);
                //添加控制指令参数-1： 后备箱开
                byteList.add((byte) 0x01);

                break;
            case FIND_CAR: //远程寻车
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x03);
                //添加指令参数长度
                byteList.add((byte) 0x01);
                //添加控制指令参数-落锁
                byteList.add((byte) 0x01);

                break;
            case LEFT_WIN_UP: //左前车窗控制-上升
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x04);
                //添加指令参数长度
                byteList.add((byte) 0x01);
                //添加控制指令参数-落锁
                byteList.add((byte) 0x01);

                break;
            case LEFT_WIN_DOWN: //左前车窗控制-下降
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x04);
                //添加指令参数长度
                byteList.add((byte) 0x01);
                //添加控制指令参数-落锁
                byteList.add((byte) 0x02);

                break;
            case RIGHT_WIN_UP: //右前车窗控制-上升
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x05);
                //添加指令参数长度
                byteList.add((byte) 0x01);
                //添加控制指令参数-落锁
                byteList.add((byte) 0x01);

                break;
            case RIGHT_WIN_DOWN: //右前车窗控制-下降
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x05);
                //添加指令参数长度
                byteList.add((byte) 0x01);
                //添加控制指令参数-落锁
                byteList.add((byte) 0x02);

                break;
            case COND_HEAT_OPEN: //空调系统制热控制-开启
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x06);
                //添加指令参数长度
                byteList.add((byte) 0x04);
                //设置时间-最小计量单元： 1s 默认： 600S
                int timeOfCond = (int) args[1];
                byteList.addAll(D2sDataPackUtil.getWordByteList(timeOfCond));
                //温度设定-最小计量单元： 1℃ 默认： 20摄氏度
                int temp = (int) args[2];
                byteList.add(D2sDataPackUtil.getIntegerByte(temp));
                break;
            case COND_HEAT_CLOSE: //空调系统制热控制-关闭
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x06);
                //添加指令参数长度
                byteList.add((byte) 0x04);
                //设置时间-最小计量单元： 1s 默认： 600S
                int timeOfCond1 = (int) args[1];
                byteList.addAll(D2sDataPackUtil.getWordByteList(timeOfCond1));
                //温度设定-最小计量单元： 1℃ 默认： 20摄氏度
                int temp1 = (int) args[2];
                byteList.add(D2sDataPackUtil.getIntegerByte(temp1));
                break;
            case COND_COLD_OPEN: //空调系统制冷控制-开启
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x07);
                //添加指令参数长度
                byteList.add((byte) 0x04);
                //设置时间-最小计量单元： 1s 默认： 600S
                int timeOfCond2 = (int) args[1];
                byteList.addAll(D2sDataPackUtil.getWordByteList(timeOfCond2));
                //温度设定-最小计量单元： 1℃ 默认： 20摄氏度
                int temp2 = (int) args[2];
                byteList.add(D2sDataPackUtil.getIntegerByte(temp2));
                break;
            case COND_COLD_CLOSE: //空调系统制冷控制-关闭
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x07);
                //添加指令参数长度
                byteList.add((byte) 0x04);
                //设置时间-最小计量单元： 1s 默认： 600S
                int timeOfCond3 = (int) args[1];
                byteList.addAll(D2sDataPackUtil.getWordByteList(timeOfCond3));
                //温度设定-最小计量单元： 1℃ 默认： 20摄氏度
                int temp3 = (int) args[2];
                byteList.add(D2sDataPackUtil.getIntegerByte(temp3));
                break;
            case VEHICLE_POWER_ON: //车辆动力通断控制-动力导通
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x08);
                //添加指令参数长度
                byteList.add((byte) 0x01);
                //添加控制指令参数-落锁
                byteList.add((byte) 0x01);

                break;
            case VEHICLE_POWER_OFF: //车辆动力通断控制-动力断开
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x08);
                //添加指令参数长度
                byteList.add((byte) 0x01);
                //添加控制指令参数-落锁
                byteList.add((byte) 0x00);

                break;
            case LITTLE_LIGHT_ON: //小灯控制-开
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x09);
                //添加指令参数长度
                byteList.add((byte) 0x01);
                //添加控制指令参数-落锁
                byteList.add((byte) 0x01);

                break;
            case LITTLE_LIGHT_OFF: //小灯控制-关
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x09);
                //添加指令参数长度
                byteList.add((byte) 0x01);
                //添加控制指令参数-落锁
                byteList.add((byte) 0x02);

                break;
            case TBOX_WAKE_UP: //车机唤醒
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x12);
                //添加指令参数长度
                byteList.add((byte) 0x01);
                //车机唤醒
                byteList.add((byte) 0x01);

                break;
            case TBOX_POWER_OFF: //车机关机
                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x83);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x12);
                //添加指令参数长度
                byteList.add((byte) 0x01);
                //车机关机
                byteList.add((byte) 0x00);

                break;
            case TBOX_UPDATE: //终端升级
                int length = 1;
                //命令标识-车载终端控制命令
                byteList.set(2, (byte) 0x82);
                //命令包
                byteList.set(3, (byte) 0xFE);

                //添加控制指令数量
                byteList.add((byte) 0x01);
                //添加控制指令ID
                byteList.add((byte) 0x01);
                //添加指令参数长度
                byteList.add((byte) length);

                //命令标识-车辆控制命令
                byteList.set(2, (byte) 0x82);
                //命令包
                byteList.set(3, (byte) 0xFE);
                /**
                 * 远程升级： 根据需要组合升级参数，参数之间用半角分号分隔。
                 *指令如下： “URL 地址;拨号点名称;拨号用户名;拨号密码;地址;端口;生产厂商代码;硬件
                 *版本;固件版本；连接到升级服务器时限” ，若某个参数无值，则为空。 远程升级操作
                 *建议但不限于采用 FTP 方式进行操作。 数据定义见表 7.62。
                 */
                String config = (String) args[1];//配置字符串
                byte[] configArr = config.getBytes();
                length = configArr.length;//设置命令长度
                for (int i = 0; i < configArr.length; i++) {
                    byteList.add(configArr[i]);
                }

                break;
            case ALARM_PARAM_QUERY: //报警参数查询
                //命令标识-报警参数查询
                byteList.set(2, (byte) 0x84);
                //命令包
                byteList.set(3, (byte) 0xFE);
                //参数查询时间
                byte[] queryTimeOfAlarm = D2sDataPackUtil.date2buf(System.currentTimeMillis());
                for (int i = 0; i < queryTimeOfAlarm.length; i++) {
                    byteList.add(time[i]);
                }

                break;
            case ALARM_PARAM_SET: //报警参数设置
                //命令标识-报警参数查询
                byteList.set(2, (byte) 0x85);
                //命令包
                byteList.set(3, (byte) 0xFE);
                //参数设置时间
                byte[] setTimeOfAlarm = D2sDataPackUtil.date2buf(System.currentTimeMillis());
                for (int i = 0; i < setTimeOfAlarm.length; i++) {
                    byteList.add(time[i]);
                }
                //参数列表,前台传递参数设置json字符串。
                break;
            case GET_RUN_INFO: //获取车辆运行数据
                //命令标识-报警参数查询
                byteList.set(2, (byte) 0x86);
                //命令包
                byteList.set(3, (byte) 0xFE);
                //参数查询时间
                byte[] queryTimeOfRun = D2sDataPackUtil.date2buf(System.currentTimeMillis());
                for (int i = 0; i < queryTimeOfRun.length; i++) {
                    byteList.add(time[i]);
                }

                break;
        }
                /*====================end---判断msgId回复消息---end====================*/
        //填充校验码占位符
        byteList.add((byte) 0xFF);
        // add to buffer
        byte[] responseBytes = new byte[byteList.size()];
        for (int i = 0; i < responseBytes.length; i++) {
            responseBytes[i] = byteList.get(i);
        }
        //添加包体长度和校验码
        responseBytes = D2sDataPackUtil.addCheck(responseBytes);
        //打印调试信息
        D2sDataPackUtil.debug(ByteBufUtil.hexDump(responseBytes));

        // return
        return Unpooled.wrappedBuffer(responseBytes);


    }

    protected static byte[] decode(char[] data) {
        int len = data.length;
        if ((len & 1) != 0) {
            throw new RuntimeException("Odd number of characters.");
        } else {
            byte[] out = new byte[len >> 1];
            int i = 0;

            for (int j = 0; j < len; ++i) {
                int f = toDigit(data[j], j) << 4;
                ++j;
                f |= toDigit(data[j], j);
                ++j;
                out[i] = (byte) (f & 255);
            }

            return out;
        }
    }

    protected static int toDigit(char ch, int index) {
        int digit = Character.digit(ch, 16);
        if (digit == -1) {
            throw new RuntimeException("Illegal hexadecimal character " + ch + " at index " + index);
        } else {
            return digit;
        }
    }

    public static void main(String[] args) throws Exception {
//        CommandFactoryD2s cmd = new CommandFactoryD2s();
//        // cmd.createCommand(CommandType.CLOSE_DOOR, 0x01);
//        cmd.createCommand(CommandType.COND_COLD_CLOSE, "600810915F2102811", 1000, 28);
        String deviceCode = "3630303831303931354632313032383131";
        byte[] dd = decode(deviceCode.toCharArray());
        System.out.println(dd.length);
        String code = "600810915F2102811";


        System.out.println(code.length());

    }
}
