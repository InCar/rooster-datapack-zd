package com.incarcloud.rooster.datapack;


import com.incarcloud.rooster.util.D2sDataPackUtil;
import io.netty.buffer.ByteBuf;
import io.netty.buffer.ByteBufUtil;
import io.netty.buffer.Unpooled;
import io.netty.util.ReferenceCountUtil;

import javax.xml.bind.DatatypeConverter;
import java.math.BigDecimal;
import java.util.*;

/**
 * zd d2s parser.
 * User: chenz
 * Date: 2017/9/5
 * Time: 11:00
 */
public class DataParserD2s implements IDataParser {
    /**
     * 协议分组和名称
     */
    public static final String PROTOCOL_GROUP = "china";
    public static final String PROTOCOL_NAME = "d2s";
    public static final String PROTOCOL_VERSION = "2017.5";
    public static final String PROTOCOL_PREFIX = PROTOCOL_GROUP + "-" + PROTOCOL_NAME + "-";

    //国标协议最小长度
    private static final int GB_LENGTH = 25;

    static {
        /**
         * 声明数据包版本与解析器类关系
         */
        DataParserManager.register(PROTOCOL_PREFIX + PROTOCOL_VERSION, DataParserD2s.class);
    }

    /**
     * 数据包准许最大容量2M
     */
    private static final int DISCARDS_MAX_LENGTH = 1024 * 1024 * 2;

    /**
     * 数据包校验
     * 采用 BCC（异或校验）法，校验范围从命令单元的第
     * 一个字节开始，同后一字节异或，直到校验码前一
     * 字节为止，校验码占用一个字节
     *
     * @param buffer
     * @return
     */
    public byte[] validate(byte[] buffer) {
        int offset = 0;//起始位置
        int packetSize = buffer.length;//数据包长度
        // D2S车型校验
        if (buffer[offset] == (byte) 0x23 && buffer[offset + 1] == (byte) 0x23) {
            try {
                int crc = buffer[offset + 2] & 0xFF;
                for (int i = offset + 3; i < offset + packetSize - 1; i++) {
                    crc = crc ^ (buffer[i] & 0xFF);
                }
                if (crc != (buffer[offset + packetSize - 1] & 0xFF)) {
                    return null;
                } else {
                    return buffer;
                }
            } catch (Exception e) {
            }
        }
        return null;
    }

    @Override
    public List<DataPack> extract(ByteBuf buffer) {
        /**
         * ## D2S数据包格式,基于电动车国标协议 ###
         * 协议应采用大端模式的网络字节序来传递字和双字
         * # 1.起始符 固定为 ASCII 字符‘##’，用“0x23,0x23”表示
         * # 2.命令单元
         * # 3.ICCID后17位
         * # 4.数据加密方式
         * # 5.数据单元长度
         * # 6.数据单元
         * # 7.校验码
         */
        DataPack dataPack;
        List<DataPack> dataPackList = new ArrayList<>();

        //长度大于2M的数据直接抛弃(恶意数据)
        if (DISCARDS_MAX_LENGTH < buffer.readableBytes()) {
            buffer.clear();
        }

        //// 遍历
        int offset1;
        while (buffer.isReadable()) {
            offset1 = buffer.readerIndex();
            //查找协议头标识--->0x23开头
            if (buffer.getByte(offset1) == (byte) 0x23 && buffer.getByte(offset1 + 1) == (byte) 0x23) {
                if (buffer.readableBytes() > GB_LENGTH) {
                    //记录读取的位置
                    buffer.markReaderIndex();
                    //获取协议头
                    byte[] header = new byte[24];
                    //写入协议头数据
                    buffer.readBytes(header);
                    //获取包体长度
                    byte[] length = new byte[2];
                    System.arraycopy(header, 22, length, 0, 2);

                    int bit32 = 0;
                    bit32 = length[0] & 0xFF;
                    bit32 = bit32 << 8;
                    bit32 |= (length[1] & 0xFF);

                    if (buffer.readableBytes() < bit32) {
                        buffer.resetReaderIndex();
                        break;
                    }

                    //重置读指针的位置,最终读取的数据需要包含头部信息
                    buffer.resetReaderIndex();
                    //数据包总长度为包头24+包体长度+包尾1
                    ByteBuf data = buffer.readBytes(bit32 + 25);
                    //创建存储数组
                    byte[] dataBytes = new byte[bit32 + 25];
                    //读取数据到数组
                    data.readBytes(dataBytes);
                    //数据包校验
                    boolean check = false;
                    int offset = 0;//起始位置
                    int packetSize = dataBytes.length;//数据包长度
                    // D2S车型校验
                    if (dataBytes[offset] == (byte) 0x23 && dataBytes[offset + 1] == (byte) 0x23) {
                        int crc = dataBytes[offset + 2] & 0xFF;
                        for (int i = offset + 3; i < offset + packetSize - 1; i++) {
                            crc = crc ^ (dataBytes[i] & 0xFF);
                        }
                        if (crc != (dataBytes[offset + packetSize - 1] & 0xFF)) {
                            check = false;
                        } else {
                            check = true;
                        }
                    }

                    //打包
                    if (check) {
                        dataPack = new DataPack(PROTOCOL_GROUP, PROTOCOL_NAME, PROTOCOL_VERSION);
                        ByteBuf buf = Unpooled.wrappedBuffer(dataBytes);
                        dataPack.setBuf(buf);
                        dataPackList.add(dataPack);
                    }
//                    else {
//                        //数据包检验不通过，跳过数据
//                        buffer.skipBytes(packetSize);
//                    }
                }
            } else {
                //协议头不符合，跳过这个字节
                buffer.skipBytes(1);
            }
        }
        //扔掉已读数据
        buffer.discardReadBytes();
        return dataPackList;
    }

    @Override
    public ByteBuf createResponse(DataPack requestPack, ERespReason reason) {
        if (null != requestPack && null != reason) {
            // 原始数据
            byte[] dataPackBytes = validate(Base64.getDecoder().decode(requestPack.getDataB64()));
            if (null != dataPackBytes) {
                // 初始化List容器，装载【消息头+消息体】
                List<Byte> byteList = new ArrayList<>();
                //头部信息
                byteList.add((byte) 0x23);
                byteList.add((byte) 0x23);
                // 预留回复命令字位置-命令标识
                byteList.add((byte) 0xFF);
                //预留回复命令字位置-应答标识
                byteList.add((byte) 0xFF);
                //设置iccid
                byte[] vinArr = D2sDataPackUtil.getRange(dataPackBytes, 4, 21);
                for (int i = 0; i < vinArr.length; i++) {
                    byteList.add(vinArr[i]);
                }
                //数据加密方式
                byteList.add((byte) 0);
                //数据单元长度
                byteList.add((byte) 0);
                byteList.add((byte) 0);

                /*====================begin-判断msgId回复消息-begin====================*/
                // 消息ID
                int msgId = dataPackBytes[1] & 0xFF;
                int msgLength = 0;
                byte statusCode;

                // 根据msgId回复信息，否则使用通用应答
                switch (msgId) {
                    case 0x01: // 0x01 - 车辆登入
                        //命令标识
                        byteList.set(2, (byte) 0x01);
                        //应答标识 成功
                        byteList.set(3, (byte) 0x01);
                        break;
                    case 0x05:// 0x05 - 车辆登出
                        //命令标识
                        byteList.set(2, (byte) 0x05);
                        //应答标识 成功
                        byteList.set(3, (byte) 0x01);
                        break;
                    case 0x08:// 0x08 - 终端校时
                        //命令标识
                        byteList.set(2, (byte) 0x08);
                        //应答标识 成功
                        byteList.set(3, (byte) 0x01);
                        break;
                }
                /*====================end---判断msgId回复消息---end====================*/
                //添加时间
                byte[] time = D2sDataPackUtil.date2buf(System.currentTimeMillis());
                for (int i = 0; i < time.length; i++) {
                    byteList.add(time[i]);
                }
                //填充校验码
                byteList.add((byte) 0xFF);
                // add to buffer
                byte[] responseBytes = new byte[byteList.size()];
                for (int i = 0; i < responseBytes.length; i++) {
                    responseBytes[i] = byteList.get(i);
                }
                responseBytes = D2sDataPackUtil.addCheck(responseBytes);

                // return
                return Unpooled.wrappedBuffer(responseBytes);
            }
        }
        return null;
    }

    @Override
    public void destroyResponse(ByteBuf responseBuf) {
        if (null != responseBuf) {
            ReferenceCountUtil.release(responseBuf);
        }
    }

    @Override
    public List<DataPackTarget> extractBody(DataPack dataPack) {
        ByteBuf buffer = null;
        List<DataPackTarget> dataPackTargetList = null;
        //  byte[] dataPackBytes = validate(Base64.getDecoder().decode(dataPack.getDataB64()));
        byte[] dataPackBytes = dataPack.getDataBytes();

        if (null != dataPackBytes) {
            // 声明变量信息
            dataPackTargetList = new ArrayList<>();
            DataPackObject dataPackObject = new DataPackObject(dataPack);
            DataPackPosition dataPackPosition;//车辆位置信息
            DataPackAlarm dataPackAlarm;//车辆报警数据
            DataPackStatus dataPackStatus;//车辆状态

            try {
                // 初始化ByteBuf
                buffer = Unpooled.wrappedBuffer(dataPackBytes);
                //获取命令ID
                int msgId = dataPackBytes[2] & 0xFF;
                D2sDataPackUtil.debug("命令ID: " + msgId);
                //获取应答标识
                int resId = dataPackBytes[3] & 0xFF;
                D2sDataPackUtil.debug("应答标识: " + resId);
                //获取iccid ICCID 的后 17 位，由 17 位字码构成，字码应符合GB16735 中 4.5 的规定
                String iccid = new String(D2sDataPackUtil.getRange(dataPackBytes, 4, 21));
                dataPackObject.setDeviceId(iccid);//设备ID
                //设置数据接收时间
                dataPackObject.setReceiveTime(new Date());
                //获取数据加密方式0x00：数据不加密；0x01：数据经过 RSA 算法加密；0xFF：无效数据；其他预留
                int msgEncryptMode = dataPackBytes[21] & 0xFF;
                D2sDataPackUtil.debug("加密方式: " + msgEncryptMode);
                switch (msgEncryptMode) {
                    case 0:
                        // 消息体不加密
                        D2sDataPackUtil.debug("--消息体不加密");
                        break;
                    case 1:
                        // 第 10 位为 1，表示消息体经过 RSA 算法加密
                        D2sDataPackUtil.debug("--RSA 算法加密");
                        dataPackObject.setEncryptName("RSA");
                    case 0xFF:
                        // 第 10 位为 1，表示消息体经过 RSA 算法加密
                        D2sDataPackUtil.debug("--无效数据");
                        break;
                }
                //获取数据单元长度
                int msgLength = (dataPackBytes[22] & 0xff) << 8 | (dataPackBytes[23] & 0xff);
                D2sDataPackUtil.debug("数据单元长度: " + msgLength);


                /**
                 * 解析消息体数据
                 */
                switch (msgId) {
                    case 0x01://车辆登入
                        System.out.println("车辆登入");
                        //读取消息头部24个byte
                        buffer.readBytes(24);
                        DataPackLogInOut dataPackLogin = new DataPackLogInOut(dataPackObject);
                        dataPackLogin.setLoginType(0);//设置车辆登录类型为车辆登入
                        //数据采集时间
                        byte[] loginTimeBuf = new byte[6];
                        buffer.readBytes(loginTimeBuf);
                        // dataPackLogin.setReceiveTime(new Date(D2sDataPackUtil.buf2Date(loginTimeBuf, 0)));

                        // 6.检验时间=数据采集时间
                        dataPackObject.setDetectionTime(new Date(D2sDataPackUtil.buf2Date(loginTimeBuf, 0)));
                        //登入流水号
                        int serialNoLogin = D2sDataPackUtil.readInt2(buffer);
                        dataPackLogin.setSerialNo(serialNoLogin);
                        //车辆识别码(VIN)
                        byte[] vinBuf = new byte[20];
                        buffer.readBytes(vinBuf);
                        dataPackLogin.setVin(new String(vinBuf));//vin
                        //  dataPackLogin.setDeviceId(iccid);//设备ID
                        //可充电蓄能子系统数 n
                        int sysNumber = buffer.readByte();
                        dataPackLogin.setSysNumber(sysNumber);
                        //可充电储能系统编码长度 m
                        int codeLength = buffer.readByte();
                        dataPackLogin.setCodeLength(codeLength);
                        //可充电储能系统编码
                        String sysCode = null;
                        if (sysNumber > 0 && codeLength > 0) {
                            byte[] sysCodeBuf = new byte[sysNumber * codeLength];
                            buffer.readBytes(sysCodeBuf);
                            sysCode = new String(sysCodeBuf);
                            dataPackLogin.setSysCode(sysCode);
                        }
                        //--add
                        dataPackTargetList.add(new DataPackTarget(dataPackLogin));
                        break;
                    case 0x02://车辆运行信息上报
                        //获取数据包体

                        byte[] dataBuffer = new byte[msgLength - 6];
                        //读取消息头部24个byte
                        buffer.readBytes(24);

                        //数据采集时间
                        byte[] collectTimeBuf = new byte[6];
                        buffer.readBytes(collectTimeBuf);
                        //数据采集时间
                        Date detectionTime = new Date(D2sDataPackUtil.buf2Date(collectTimeBuf, 0));
                        // 6.检验时间
                        dataPackObject.setDetectionTime(detectionTime);
                        //读取消息体数据到byte数组
                        buffer.readBytes(dataBuffer);
                        D2sDataPackUtil.debug("车辆运行信息上报:" + ByteBufUtil.hexDump(dataBuffer));

                        if (dataBuffer != null && dataBuffer.length > 0) {
                            int index = 0;
                            while (index < (msgLength - 6)) {
                                if (dataBuffer[index] == (byte) 0x01) { // 动力蓄电池电气数据
                                    DataPackBattery dataPackBattery = new DataPackBattery(dataPackObject);
                                    dataPackBattery.setDetectionTime(detectionTime);

                                    //设置deviceCode
                                    //  dataPackBattery.setVin(iccid);
                                    dataPackBattery.setDeviceId(iccid);
                                    index += 1;
                                    int length = 11 + (dataBuffer[index + 10] & 0xFF) * 2;
                                    byte[] eleBuffer = new byte[length];
                                    System.arraycopy(dataBuffer, index, eleBuffer, 0, length);
                                    //打印调试信息
                                    D2sDataPackUtil.debug("动力蓄电池电气数据--->" + ByteBufUtil.hexDump(eleBuffer));
                                    //动力蓄电池字子系统个数
                                    Integer batterySysNumber = eleBuffer[0] & 0xFF;
                                    dataPackBattery.setBatterySysNumber(batterySysNumber);
                                    //电池子系统号
                                    Integer batterySysIndex = eleBuffer[1] & 0xFF;
                                    dataPackBattery.setBatterySysIndex(batterySysIndex);
                                    //动力蓄电池电压
                                    Float totalVoltage = (float) ((eleBuffer[2] & 0xFF) << 8 | (eleBuffer[3] & 0xFF)) / 10;
                                    totalVoltage = new BigDecimal(totalVoltage).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackBattery.setTotalVoltage(totalVoltage);
                                    //动力蓄电池电流
                                    Float totalCurrent = (float) ((eleBuffer[4] & 0xFF) << 8 | (eleBuffer[5] & 0xFF)) / 10 - 1000;
                                    totalCurrent = new BigDecimal(totalCurrent).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackBattery.setTotalCurrent(totalCurrent);
                                    //单体蓄电池总数
                                    Integer batteryNumber = (eleBuffer[6] & 0xFF) << 8 | (eleBuffer[7] & 0xFF);
                                    dataPackBattery.setBatteryNumber(batteryNumber);
                                    //本帧起始电池序号
                                    Integer batteryStartIndex = (eleBuffer[8] & 0xFF) << 8 | (eleBuffer[9] & 0xFF);
                                    dataPackBattery.setBatterySysIndex(batteryStartIndex);
                                    //本帧单体电池总数
                                    Integer batteryPacketNumber = eleBuffer[10] & 0xFF;
                                    dataPackBattery.setBatteryPacketNumber(batteryPacketNumber);
                                    //单体电压数组
                                    List<Float> batteryVoltageList = new ArrayList<>();
                                    for (int i = 0; i < batteryPacketNumber; i++) {
                                        batteryVoltageList.add(new BigDecimal(((float) ((eleBuffer[11 + i * 2] & 0xFF) << 8 | (eleBuffer[12 + i * 2] & 0xFF)) / 1000)).setScale(3, BigDecimal.ROUND_HALF_UP).floatValue());
                                    }
                                    dataPackBattery.setBatteryVoltages(batteryVoltageList);
                                    //-add
                                    dataPackTargetList.add(new DataPackTarget(dataPackBattery));
                                    //索引增加
                                    index = index + length;
                                } else if (dataBuffer[index] == (byte) 0x02) { // 动力蓄电池包温度数据
                                    DataPackTemperature dataPackTemperature = new DataPackTemperature(dataPackObject);
                                    dataPackTemperature.setDetectionTime(detectionTime);
                                    //设置vin码
                                    dataPackTemperature.setDeviceId(iccid);
                                    index += 1;
                                    int length = 4 + ((dataBuffer[index + 2] & 0xFF << 8) | (dataBuffer[index + 3] & 0xFF));
                                    byte[] eleBuffer = new byte[length];
                                    System.arraycopy(dataBuffer, index, eleBuffer, 0, length);
                                    //打印调试信息
                                    D2sDataPackUtil.debug("动力蓄电池电气数据--->" + ByteBufUtil.hexDump(eleBuffer));
                                    //动力蓄电池总成个数
                                    Integer batterySysNumber = eleBuffer[0] & 0xFF;
                                    dataPackTemperature.setBatterySysNumber(batterySysNumber);
                                    //电池子系统号
                                    Integer sysIndex = eleBuffer[1] & 0xFF;
                                    dataPackTemperature.setSysIndex(sysIndex);
                                    //电池温度探针个数
                                    Integer number = (eleBuffer[2] & 0xFF) << 8 | (eleBuffer[3] & 0xFF);
                                    dataPackTemperature.setNumber(number);
                                    //电池总各温度探针检测到的温度值
                                    List<Integer> temperatureList = new ArrayList<>();
                                    for (int i = 0; i < number; i++) {
                                        temperatureList.add((eleBuffer[4 + i] & 0xFF) - 40);
                                    }
                                    dataPackTemperature.setTemperatureList(temperatureList);
                                    //-add
                                    dataPackTargetList.add(new DataPackTarget(dataPackTemperature));
                                    index = index + length;
                                } else if (dataBuffer[index] == (byte) 0x03) { // 整车数据
                                    DataPackOverview dataPackOverview = new DataPackOverview(dataPackObject);
                                    //     dataPackOverview.setVin(iccid);
                                    index += 1;
                                    int length = 20;
                                    byte[] eleBuffer = new byte[length];
                                    System.arraycopy(dataBuffer, index, eleBuffer, 0, length);
                                    //打印调试信息
                                    D2sDataPackUtil.debug("整车数据--->" + ByteBufUtil.hexDump(eleBuffer));
                                    //车辆状态
                                    Integer vehicleStatus = eleBuffer[0] & 0xFF;
                                    dataPackOverview.setCarStatus(vehicleStatus);
                                    //充电状态
                                    Integer chargeStatus = eleBuffer[1] & 0xFF;
                                    dataPackOverview.setChargeStatus(chargeStatus);
                                    //运行模式
                                    Integer runStatus = eleBuffer[2] & 0xFF;
                                    dataPackOverview.setRunStatus(runStatus);
                                    //车速
                                    Float vehicleSpeed = (float) ((eleBuffer[3] & 0xFF) << 8 | (eleBuffer[4] & 0xFF)) / 10;
                                    vehicleSpeed = new BigDecimal(vehicleSpeed).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackOverview.setVehicleSpeed(vehicleSpeed);
                                    //累计里程
                                    Double mileAge = (double) ((eleBuffer[5] & 0xFF) << 24 | (eleBuffer[6] & 0xFF) << 16 | (eleBuffer[7] & 0xFF) << 8 | (eleBuffer[8] & 0xFF));
                                    mileAge = new BigDecimal(mileAge).setScale(1, BigDecimal.ROUND_HALF_UP).doubleValue();
                                    dataPackOverview.setMileage(mileAge);
                                    //总电压
                                    Float totalVoltage = (float) ((eleBuffer[9] & 0xFF) << 8 | (eleBuffer[10] & 0xFF)) / 10;
                                    totalVoltage = new BigDecimal(totalVoltage).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackOverview.setVoltage(totalVoltage);
                                    //总电流
                                    Float totalCurrent = (float) ((eleBuffer[11] & 0xFF) << 8 | (eleBuffer[12] & 0xFF)) / 10 - 1000;
                                    totalCurrent = new BigDecimal(totalCurrent).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackOverview.setTotalCurrent(totalCurrent);
                                    //SOC
                                    Integer soc = eleBuffer[13] & 0xFF;
                                    dataPackOverview.setSoc(soc);
                                    //DC-DC 状态
                                    Integer dcdcStatus = eleBuffer[14] & 0xFF;
                                    dataPackOverview.setDcdcStatus(dcdcStatus);
                                    //档位
                                    Integer clutchStatus = eleBuffer[15] & 0x0F;
                                    dataPackOverview.setClutchStatus(clutchStatus);
                                    //制动状态
                                    Integer driveBrakeStatus = eleBuffer[15] >>> 4 & 0x03;
                                    dataPackOverview.setDriveBrakeStatus(driveBrakeStatus);
                                    //绝缘电阻
                                    Integer issueValue = (eleBuffer[16] & 0xFF) << 8 | eleBuffer[17] & 0xFF;
                                    dataPackOverview.setIssueValue(issueValue);
                                    //-add
                                    dataPackTargetList.add(new DataPackTarget(dataPackOverview));
                                    index = index + length;

                                } else if (dataBuffer[index] == (byte) 0x04) { // 汽车电机部分数据
                                    index += 1;
                                    int length = 13;
                                    DataPackMotor dataPackMotor = new DataPackMotor(dataPackObject);
                                    dataPackMotor.setDetectionTime(detectionTime);
                                    //        dataPackMotor.setVin(iccid);
                                    byte[] eleBuffer = new byte[length];
                                    System.arraycopy(dataBuffer, index, eleBuffer, 0, length);
                                    //打印调试信息
                                    D2sDataPackUtil.debug("汽车电机部分数据--->" + ByteBufUtil.hexDump(eleBuffer));
                                    //电机个数
                                    Integer motorNumber = eleBuffer[0] & 0xFF;
                                    dataPackMotor.setMotorTotal(motorNumber);
                                    //电机序号
                                    Integer motorIndex = eleBuffer[1] & 0xFF;
                                    dataPackMotor.setMotorSeq(motorIndex);
                                    //驱动电机状态
                                    Integer motorStatus = eleBuffer[2] & 0xFF;
                                    dataPackMotor.setMotorStatus(motorStatus);
                                    //驱动电机控制器温度
                                    Integer motorControlerTemperature = (eleBuffer[3] & 0xFF) - 40;
                                    dataPackMotor.setControllerTemperature(motorControlerTemperature);
                                    //驱动电机转速
                                    Integer motorRpm = ((eleBuffer[4] & 0xFF) << 8 | eleBuffer[5] & 0xFF) - 20000;
                                    dataPackMotor.setSpeed(motorRpm);
                                    //驱动电机转矩
                                    Float motorNm = (float) (((eleBuffer[6] & 0xFF) << 8 | (eleBuffer[7] & 0xFF)) - 20000) / 10;
                                    motorNm = new BigDecimal(motorNm).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackMotor.setTorque(motorNm);
                                    //驱动电机温度
                                    Integer motorTemperature = (eleBuffer[8] & 0xFF) - 40;
                                    dataPackMotor.setMotorTemperature(motorTemperature);
                                    //电机控制器输入电压
                                    Float motorInputVoltage = (float) ((eleBuffer[9] & 0xFF) << 8 | (eleBuffer[10] & 0xFF)) / 10;
                                    motorInputVoltage = new BigDecimal(motorInputVoltage).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackMotor.setControllerInputVoltage(motorInputVoltage);
                                    //电机控制器直流母线电流
                                    Float motorBusCurrent = (float) ((eleBuffer[11] & 0xFF) << 8 | (eleBuffer[12] & 0xFF)) / 10 - 1000;
                                    motorBusCurrent = new BigDecimal(motorBusCurrent).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackMotor.setControllerDirectCurrent(motorBusCurrent);
                                    //-add
                                    dataPackTargetList.add(new DataPackTarget(dataPackMotor));
                                    index = index + length;

                                } else if (dataBuffer[index] == (byte) 0x07) { // 车辆位置数据
                                    index += 1;
                                    int length = 21;
                                    dataPackPosition = new DataPackPosition(dataPackObject);
                                    dataPackPosition.setDetectionTime(detectionTime);
                                    //      dataPackPosition.setVin(iccid);
                                    dataPackPosition.setPositionTime(Calendar.getInstance().getTime());
                                    byte[] eleBuffer = new byte[length];
                                    System.arraycopy(dataBuffer, index, eleBuffer, 0, length);
                                    //打印调试信息
                                    D2sDataPackUtil.debug("车辆位置数据--->" + ByteBufUtil.hexDump(eleBuffer));
                                    //定位状态
                                    Integer isValidate = eleBuffer[0] & 0x01;
                                    dataPackPosition.setIsValidate(isValidate);
                                    //0:北纬； 1:南纬
                                    Integer latType = eleBuffer[0] & 0x02;
                                    //0:东经； 1:西经
                                    Integer lngType = eleBuffer[0] & 0x04;
                                    //经度
                                    Double longitude = (double) ((eleBuffer[1] & 0xFF) << 24 | (eleBuffer[2] & 0xFF) << 16 | (eleBuffer[3] & 0xFF) << 8 | (eleBuffer[4] & 0xFF)) * 0.000001f;
                                    longitude = new BigDecimal(longitude).setScale(6, BigDecimal.ROUND_HALF_UP).doubleValue();
                                    dataPackPosition.setLongitude(longitude);
                                    //纬度
                                    Double latitude = (double) ((eleBuffer[5] & 0xFF) << 24 | (eleBuffer[6] & 0xFF) << 16 | (eleBuffer[7] & 0xFF) << 8 | (eleBuffer[8] & 0xFF)) * 0.000001f;
                                    latitude = new BigDecimal(latitude).setScale(6, BigDecimal.ROUND_HALF_UP).doubleValue();
                                    dataPackPosition.setLatitude(latitude);
                                    //速度
                                    Float speed = (float) ((eleBuffer[9] & 0xFF) << 8 | (eleBuffer[10] & 0xFF)) / 10;
                                    speed = new BigDecimal(speed).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackPosition.setSpeed(speed);
                                    //海拔
                                    Double altitude = (double) ((eleBuffer[11] & 0xFF) << 24 | (eleBuffer[12] & 0xFF) << 16 | (eleBuffer[13] & 0xFF) << 8 | (eleBuffer[14] & 0xFF)) / 10;
                                    altitude = new BigDecimal(altitude).setScale(1, BigDecimal.ROUND_HALF_UP).doubleValue();
                                    dataPackPosition.setAltitude(altitude);
                                    //方向
                                    Float direction = (float) ((eleBuffer[15] & 0xFF) << 8 | (eleBuffer[16] & 0xFF));
                                    dataPackPosition.setDirection(direction);
                                    dataPackTargetList.add(new DataPackTarget(dataPackPosition));
                                    index = index + length;

                                } else if (dataBuffer[index] == (byte) 0x08) { // 极值数据
                                    index += 1;
                                    int length = 14;
                                    DataPackPeak dataPackPeak = new DataPackPeak(dataPackObject);
                                    dataPackPeak.setDetectionTime(detectionTime);
                                    List<DataPackPeak.Peak> peakList = new ArrayList<>();
                                    //     dataPackPeak.setVin(iccid);
                                    byte[] eleBuffer = new byte[length];
                                    System.arraycopy(dataBuffer, index, eleBuffer, 0, length);
                                    //打印调试信息
                                    D2sDataPackUtil.debug("极值数据--->" + ByteBufUtil.hexDump(eleBuffer));

                                    //最高电压电池子系统号
                                    Integer batterySystemMaxNo = eleBuffer[0] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最高电压电池子系统号",
                                            batterySystemMaxNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));

                                    //最高电压电池单体代号
                                    Integer batteryVoltageMaxNo = eleBuffer[1] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最高电压电池单体代号",
                                            batteryVoltageMaxNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));

                                    //电池单体电压最高值
                                    Float batteryVoltageMaxValue = (float) ((eleBuffer[2] & 0xFF) << 8 | (eleBuffer[3] & 0xFF)) / 1000;
                                    batteryVoltageMaxValue = new BigDecimal(batteryVoltageMaxValue).setScale(3, BigDecimal.ROUND_HALF_UP).floatValue();
                                    peakList.add(new DataPackPeak.Peak(null, "电池单体电压最高值",
                                            batteryVoltageMaxValue.toString(), "V", "有效值范围： 0～15000（表示 0V～15V）"));

                                    //最低电压电池子系统号
                                    Integer batterySystemMinNo = eleBuffer[4] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最低电压电池子系统号",
                                            batterySystemMinNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));


                                    //最低电压电池单体代号
                                    Integer batteryVoltageMinNo = eleBuffer[5] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最低电压电池单体代号",
                                            batteryVoltageMinNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));


                                    //电池单体电压最低值
                                    Float batteryVoltageMinValue = (float) ((eleBuffer[6] & 0xFF) << 8 | (eleBuffer[7] & 0xFF)) / 1000;
                                    batteryVoltageMinValue = new BigDecimal(batteryVoltageMinValue).setScale(3, BigDecimal.ROUND_HALF_UP).floatValue();
                                    peakList.add(new DataPackPeak.Peak(null, "最高电压电池单体代号",
                                            batteryVoltageMinValue.toString(), "V", "有效值范围： 0～15000（表示 0V～15V）"));


                                    //最高温度子系统号
                                    Integer temperatureHighestSystemNo = eleBuffer[8] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最高温度子系统号",
                                            temperatureHighestSystemNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));


                                    //最高温度探针单体代号
                                    Integer temperatureHighestNo = eleBuffer[9] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最高温度探针单体代号",
                                            temperatureHighestNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));

                                    //蓄电池中最高温度值
                                    Integer temperatureHighestValue = (eleBuffer[10] & 0xFF) - 40;
                                    peakList.add(new DataPackPeak.Peak(null, "蓄电池中最高温度值",
                                            temperatureHighestValue.toString(), "℃", "有效值范围： 0～250（数值偏移量 40℃，表示-40℃～+210℃）"));

                                    //最低温度子系统号
                                    Integer temperatureLowestSystemNo = eleBuffer[11] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最低温度子系统号",
                                            temperatureLowestSystemNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));

                                    //最低温度探针子系统代号
                                    Integer temperatureLowestNo = eleBuffer[12] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最低温度探针子系统代号",
                                            temperatureLowestNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));

                                    //蓄电池中最低温度值
                                    Integer temperatureLowestValue = (eleBuffer[13] & 0xFF) - 40;
                                    peakList.add(new DataPackPeak.Peak(null, "蓄电池中最低温度值",
                                            temperatureLowestValue.toString(), "℃", "有效值范围： 0～250（数值偏移量 40℃，表示-40℃～+210℃）"));

                                    dataPackPeak.setPeakList(peakList);
                                    //-add
                                    dataPackTargetList.add(new DataPackTarget(dataPackPeak));

                                    index = index + length;
                                } else if (dataBuffer[index] == (byte) 0x09) { // 透传数据
                                    //can数据
                                    DataPackCanHvac hvac = new DataPackCanHvac(dataPackObject);//hvac数据
                                    hvac.setDetectionTime(detectionTime);
                                    hvac.setDeviceId(iccid);
                                    DataPackCanBcm bcm = new DataPackCanBcm(dataPackObject);//bcm
                                    bcm.setDetectionTime(detectionTime);
                                    bcm.setDeviceId(iccid);
                                    DataPackCanVms vms = new DataPackCanVms(dataPackObject);//vms
                                    vms.setDetectionTime(detectionTime);
                                    vms.setDeviceId(iccid);
                                    DataPackCanPeps peps = new DataPackCanPeps(dataPackObject);//peps
                                    peps.setDetectionTime(detectionTime);
                                    peps.setDeviceId(iccid);
                                    DataPackCanEps eps = new DataPackCanEps(dataPackObject);//eps
                                    eps.setDetectionTime(detectionTime);
                                    eps.setDeviceId(iccid);
                                    DataPackCanAdas adas = new DataPackCanAdas(dataPackObject);//adas
                                    adas.setDetectionTime(detectionTime);
                                    adas.setDeviceId(iccid);
                                    DataPackCanBms bms = new DataPackCanBms(dataPackObject);//bms
                                    bms.setDetectionTime(detectionTime);
                                    bms.setDeviceId(iccid);
                                    Float[] voltageArray = new Float[42]; // 单体电池电压数组
                                    Integer[] tempratureArray = new Integer[12]; // 探头温度数组
                                    DataPackCanObc obc = new DataPackCanObc(dataPackObject);//obc
                                    obc.setDetectionTime(detectionTime);
                                    obc.setDeviceId(iccid);
                                    DataPackCanMc mc = new DataPackCanMc(dataPackObject);//mc
                                    mc.setDetectionTime(detectionTime);
                                    mc.setDeviceId(iccid);

                                    index += 1;
                                    int canPacketNumber = dataBuffer[index] & 0xFF;
                                    int length = canPacketNumber * 12;
                                    index += 1;
                                    byte[] canAllBuffer = new byte[length];
                                    System.arraycopy(dataBuffer, index, canAllBuffer, 0, length);

                                    //打印调试信息
                                    D2sDataPackUtil.debug("透传数据--->" + ByteBufUtil.hexDump(canAllBuffer));

                                    int offset = 0;
                                    for (int i = 0; i < canPacketNumber; i++) {
                                        //can id
                                        int canId = D2sDataPackUtil.getInt4Bigendian(canAllBuffer, offset + i * 12, offset + i * 12 + 4);
                                        byte[] canBuffer = D2sDataPackUtil.getRange(canAllBuffer, offset + i * 12 + 4, offset + i * 12 + 12);
                                        DataPackCanVersion dataPackCanVersion = null;
                                        if (canId == (int) 0x18FF64DA) { //icu版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("icu");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("icu版本[0x18FF64DA]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF6401) { //vms版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("vms");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("vms版本[0x18FF6401]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64F4) {//bms版本

                                        } else if (canId == (int) 0x18FF64EF) {//mc版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("mc");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("mc版本[0x18FF64EF]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64DD) {//peps版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("peps");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("peps版本[0x18FF64DD]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64E5) {//obc版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("obc");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("obc版本[0x18FF64E5]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64DE) {//hvac版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("hvac");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("hvac版本[0x18FF64DE]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64E7) {//gprs版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("gprs");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("gprs版本[0x18FF64E7]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64DC) {//bcm版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("bcm");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("bcm版本[0x18FF64DC]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64DF) {//adas版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("adas");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("adas版本[0x18FF64DF]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64DB) {//gps版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("gps");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[6];
                                            System.arraycopy(canBuffer, 0, bf, 0, 6);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("gps版本[0x18FF64DB]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 6));
                                        } else if (canId == (int) 0x08FF00DD) {//peps PEPS_SEND1_MSG
                                            //打印调试信息
                                            D2sDataPackUtil.debug("PEPS_SEND1_MSG[0x08FF00DD]--->" + ByteBufUtil.hexDump(canBuffer));
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            int rkeLockCmd = (int) (bit64 & 0x0F);//遥控器状态
                                            peps.setRkelockCmd(rkeLockCmd);
                                            bit64 = bit64 >> 4;
                                            int pkeLockCmd = (int) (bit64 & 0x0F);//无钥匙进入状态
                                            peps.setPkelockCmd(pkeLockCmd);
                                            bit64 = bit64 >> 4;
                                            int pepsBcmAlarm = (int) (bit64 & 0x0F);//PepsBcmAlarm
                                            peps.setPepsbcmAlarm(pepsBcmAlarm);
                                            bit64 = bit64 >> 4;
                                            int pepsIcuAlarm = (int) (bit64 & 0x0F);//仪表报警提示
                                            peps.setPepsicuAlarm(pepsIcuAlarm);
                                            bit64 = bit64 >> 4;
                                            int pepsEscLpowerEnable = (int) (bit64 & 0x03);//ESCL电源状态
                                            peps.setPepsEsclpowerEnable(pepsEscLpowerEnable);
                                            bit64 = bit64 >> 2;
                                            int sysPowMode = (int) (bit64 & 0x03);//整车电源档位
                                            peps.setSyspowMode(sysPowMode);
                                            bit64 = bit64 >> 2;
                                            int fobIndex = (int) (bit64 & 0x07);//
                                            peps.setFobIndex(fobIndex);
                                            bit64 = bit64 >> 3;
                                            int crankRequest = (int) (bit64 & 0x01);//启动请求
                                            peps.setCrankRequest(crankRequest);
                                            bit64 = bit64 >> 1;
                                            int esclStatus = (int) (bit64 & 0x01);//ESCL状态
                                            peps.setEsclStatus(esclStatus);
                                        } else if (canId == (int) 0x08FF01DD) {//peps
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("peps[0x08FF01DD]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int fobPosition = (byte) (bit64 & 0x07);//钥匙位置
                                            peps.setFobPosition(fobPosition);
                                            bit64 = bit64 >> 3;
                                            int pepsAuthResult = (byte) (bit64 & 0x01);//认证状态
                                            peps.setAuthenticationStatus(pepsAuthResult);
                                            bit64 = bit64 >> 1;
                                            int backupKeyStatus = (byte) (bit64 & 0x01);//备用钥匙状态
                                            peps.setSpareKeyStatus(backupKeyStatus);
                                            bit64 = bit64 >> 1;
                                            int ssbSw1 = (byte) (bit64 & 0x01);//启动按键状态
                                            peps.setSsbSw1(ssbSw1);
                                            bit64 = bit64 >> 1;
                                            int ssbSw2 = (byte) (bit64 & 0x01);//启动按键状态
                                            peps.setSsbSw2(ssbSw2);
                                            bit64 = bit64 >> 1;
                                            int driverdDoorSw = (byte) (bit64 & 0x01);//驾驶门状态
                                            peps.setDriverdDoorStatus(driverdDoorSw);
                                            bit64 = bit64 >> 1;
                                            int passDoorSw = (byte) (bit64 & 0x01);//副驾门状态
                                            peps.setPassDoorSwStatus(passDoorSw);
                                            bit64 = bit64 >> 1;
                                            int trunkSw = (byte) (bit64 & 0x01);//尾门状态
                                            peps.setTrunksw(trunkSw);
                                            bit64 = bit64 >> 1;
                                            int brakeSW = (byte) (bit64 & 0x01);//制动踏板状态
                                            peps.setBrakeSw(brakeSW);
                                            bit64 = bit64 >> 1;
                                            int accFb = (byte) (bit64 & 0x01);//ACC电源状态
                                            peps.setAccFb(accFb);
                                            bit64 = bit64 >> 1;
                                            int onFb = (byte) (bit64 & 0x01);//ON电源状态
                                            peps.setOnFb(onFb);
                                            bit64 = bit64 >> 1;
                                            int accCtrl = (byte) (bit64 & 0x01);//ACC控制信号
                                            peps.setAccCtrl(accCtrl);
                                            bit64 = bit64 >> 1;
                                            int onCtrl = (byte) (bit64 & 0x01);//ON控制信号
                                            peps.setOnCtrl(onCtrl);
                                            bit64 = bit64 >> 1;
                                            int esclUnlockFb = (byte) (bit64 & 0x01);//escl解锁
                                            peps.setEsclUnlockFb(esclUnlockFb);
                                            bit64 = bit64 >> 1;
                                            int esclLockEn = (byte) (bit64 & 0x01);//escl上锁
                                            peps.setEsclLockEn(esclLockEn);
                                            bit64 = bit64 >> 1;//
                                            bit64 = bit64 >> 7;//
                                            int vSpeed = (int) (bit64 & 0xFF);//车速
                                            peps.setvSpeed(vSpeed);
                                            bit64 = bit64 >> 8;
                                            int eSpeed = (int) (bit64 & 0xFF);//电机转速
                                            peps.seteSpeed(eSpeed);
                                        } else if (canId == (int) 0x1CFF00DE) {//HVAC_General_MSG
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("HVAC_General_MSG[0x1CFF00DE]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int runstatus = (int) (bit64 & 0x03);//空调启动状态
                                            hvac.setRunStatus(runstatus);
                                            bit64 = bit64 >>> 2;
                                            int level = (int) (bit64 & 0x0F);//空调风机档位
                                            hvac.setHvacLevel(level);
                                            bit64 = bit64 >>> 4;
                                            bit64 = bit64 >>> 2;
                                            int power = (int) (bit64 & 0xFFFF);//空调功率
                                            hvac.setPower(power);
                                            bit64 = bit64 >>> 16;
                                            int exTemp = (int) (bit64 & 0xFF - 40);//车外温度
                                            hvac.setExTemp(exTemp);
                                            bit64 = bit64 >>> 8;
                                            int innerTemp = (int) (bit64 & 0xFF - 40);//车内温度
                                            hvac.setInnerTemp(innerTemp);
                                            bit64 = bit64 >>> 8;
                                            int crondDirection = (int) (bit64 & 0x07);//空调风向状态
                                            hvac.setCrondDirection(crondDirection);
                                            bit64 = bit64 >>> 3;
                                            int cirleModel = (int) (bit64 & 0x01);//空调循环模式状态
                                            hvac.setCirleModel(cirleModel);
                                        } else if (canId == (int) 0x1CFF01DE) {//HVAC_FaultList_MSG
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("HVAC_FaultList_MSG[0x1CFF01DE]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int errModel = 0;//模式电机故障
                                            if ((bit64 & 0x01) == 0x00) {
                                                errModel = 0x00;
                                            } else {
                                                errModel = 0x01;
                                            }
                                            hvac.setErrModel(errModel);
                                            bit64 = bit64 >> 1;
                                            int errTemp = 0;//温度电机故障
                                            if ((bit64 & 0x01) == 0x00) {
                                                errTemp = 0x00;
                                            } else {
                                                errTemp = 0x01;
                                            }
                                            hvac.setErrTemp(errTemp);
                                            bit64 = bit64 >> 1;
                                            int errEvalsensor = 0;//蒸发器传感器故障
                                            if ((bit64 & 0x01) == 0x00) {
                                                errEvalsensor = 0x00;
                                            } else {
                                                errEvalsensor = 0x01;
                                            }
                                            hvac.setErrEvalsensor(errEvalsensor);
                                            bit64 = bit64 >> 1;
                                            int errTempSensor = 0;//回风温度传感器故障
                                            if ((bit64 & 0x01) == 0x00) {
                                                errTempSensor = 0x00;
                                            } else {
                                                errTempSensor = 0x01;
                                            }
                                            hvac.setErrTempSensor(errTempSensor);
                                        } else if (canId == (int) 0x1CFF00DA) {//icu
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("icu[0x1CFF00DA]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float mileAge = (bit64 & 0xFFFFFF) * 0.1f;
                                            BigDecimal bigDecimal = new BigDecimal(mileAge); //总里程
                                            mileAge = bigDecimal.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            bit64 = bit64 >>> 32;
                                            int brakeSysAlarm = (int) (bit64 & 0x01); //制动系统报警
                                            bit64 = bit64 >>> 1;
                                            int keepInfo = (int) (bit64 & 0x03);
                                            bit64 = bit64 >>> 2;
                                            float leaveMileAge = (bit64 & 0xFFFF) * 0.1f;
                                            BigDecimal bigDecimal1 = new BigDecimal(mileAge); //里程
                                            leaveMileAge = bigDecimal1.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                        } else if (canId == (int) 0x0CFF00DC) {//bcm BCM_General
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BCM_General[0x0CFF00DC]--->" + ByteBufUtil.hexDump(canBuffer));
                                            Integer runStatus = (int) (bit64 & 0x0F);//BCM运行状态（阶段）
                                            bcm.setRunStatus(runStatus);

                                            bit64 = bit64 >> 4;
                                            int errLevel = (int) (bit64 & 0x03);//BCM故障等级
                                            bcm.setErrLevel(errLevel);

                                            bit64 = bit64 >> 2;
                                            int brakeStatus = (int) (bit64 & 0x01);//脚刹状态
                                            bcm.setBrakeStatus(brakeStatus);

                                            bit64 = bit64 >> 1;
                                            int handbrakeStatus = (int) (bit64 & 0x01);//手刹是否拉起
                                            bcm.setHandbrakeStatus(handbrakeStatus);

                                            bit64 = bit64 >> 1;
                                            int iscrash = (int) (bit64 & 0x01);//碰撞是否发生bit64 = bit64 >> 1;
                                            bcm.setIscrash(iscrash);

                                            bit64 = bit64 >> 1;
                                            int dc12level = (int) (bit64 & 0x0F);//12V电源档位
                                            bcm.setDc12Level(dc12level);

                                            bit64 = bit64 >> 4;
                                            bit64 = bit64 >> 1;
                                            float dc12voltage = ((float) (bit64 & 0xFF)) * 0.1f;//12V蓄电池电压
                                            BigDecimal bigDecimal = new BigDecimal(dc12voltage);
                                            dc12voltage = bigDecimal.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            bcm.setDc12Voltage(dc12voltage);

                                            bit64 = bit64 >> 8;
                                            int errTurnLight = (int) (bit64 & 0x03);//转向灯故障状态
                                            bcm.setErrTurnLight(errTurnLight);

                                            bit64 = bit64 >> 2;
                                            int leftWinOutStatus = (int) (bit64 & 0x03);//左前玻璃升降输出状态
                                            bcm.setLeftWinOutStatus(leftWinOutStatus);

                                            bit64 = bit64 >> 2;
                                            int rightWinOutStatus = (int) (bit64 & 0x03);//右前玻璃升降输出状态
                                            bcm.setRightWinOutStatus(rightWinOutStatus);

                                        } else if (canId == (int) 0x0CFF01DC) {//bcm BCM_SysSt
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BCM_SysSt[0x0CFF01DC]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int backWinIsHeat = (int) (bit64 & 0x01);//后挡风玻璃加热是否开
                                            bcm.setBackWinIsHeat(backWinIsHeat);

                                            bit64 = bit64 >>> 1;
                                            int leftWinStatus = (byte) (bit64 & 0x01);//左窗状态
                                            bcm.setLeftWinStatus(leftWinStatus);
                                            bit64 = bit64 >>> 1;
                                            int rightWinStatus = (byte) (bit64 & 0x01);//右窗错误
                                            bcm.setRightWinStatus(rightWinStatus);
                                            bit64 = bit64 >>> 1;
                                            //reserve
                                            bit64 = bit64 >>> 3;
                                            int isRemoteLightOn = (byte) (bit64 & 0x01);//远光灯是否开
                                            bcm.setIsRemoteLightOn(isRemoteLightOn);
                                            bit64 = bit64 >>> 1;
                                            int isNeerLightOn = (byte) (bit64 & 0x01);//近光灯是否开
                                            bcm.setIsNeerLightOn(isNeerLightOn);
                                            bit64 = bit64 >>> 1;
                                            int isFrontFogOn = (byte) (bit64 & 0x01);//前雾灯是否开
                                            bcm.setIsFrontFogOn(isFrontFogOn);

                                            bit64 = bit64 >>> 1;
                                            int isBackFogOn = (byte) (bit64 & 0x01);//后雾灯是否开
                                            bcm.setIsBackFogOn(isBackFogOn);
                                            bit64 = bit64 >>> 1;
                                            int isDrvLightOn = (byte) (bit64 & 0x01);//昼间行车灯是否开
                                            bcm.setIsDrvLightOn(isDrvLightOn);
                                            bit64 = bit64 >>> 1;
                                            int turnLightStatus = (int) (bit64 & 0x03);//转向灯转向方向
                                            bcm.setTurnLightOn(turnLightStatus);
                                            bit64 = bit64 >>> 2;
                                            // reserve
                                            bit64 = bit64 >>> 2;
                                            int isSmallLightOn = (byte) (bit64 & 0x01);//背光灯（小灯）是否开
                                            bcm.setIsSmallLightOn(isSmallLightOn);
                                            bit64 = bit64 >>> 1;
                                            int isReadLightOn = (byte) (bit64 & 0x01);//室内阅读灯是否开
                                            bcm.setIsReadLightOn(isReadLightOn);
                                            bit64 = bit64 >>> 1;
                                            int isBrakeLightOn = (byte) (bit64 & 0x01);//制动灯是否开
                                            bcm.setIsBrakeLightOn(isBrakeLightOn);
                                            bit64 = bit64 >>> 1;
                                            int isPosLightOn = (byte) (bit64 & 0x01);//位置灯是否开
                                            bcm.setIsPosLightOn(isPosLightOn);
                                            bit64 = bit64 >>> 1;
                                            // reserve
                                            bit64 = bit64 >>> 1;
                                            int isReverseLightOn = (byte) (bit64 & 0x01);//倒车灯是否开
                                            bcm.setIsReadLightOn(isReverseLightOn);
                                            bit64 = bit64 >>> 1;
                                            int alarmStatus = (int) (bit64 & 0x07);//防盗报警状态指示
                                            bcm.setAlarmStatus(alarmStatus);
                                            bit64 = bit64 >>> 3;
                                            // reserve
                                            bit64 = bit64 >>> 1;
                                            int backDoorLockStatus = (byte) (bit64 & 0x01);//后背门锁是否锁止
                                            bcm.setBackDoorLockStatus(backDoorLockStatus);
                                            bit64 = bit64 >>> 1;
                                            int leftDoorLockStatus = (byte) (bit64 & 0x01);//左前门门锁是否锁止
                                            bcm.setLeftDoorLockStatus(leftDoorLockStatus);
                                            bit64 = bit64 >>> 1;
                                            int rightDoorLockStatus = (byte) (bit64 & 0x01);//右前门门锁是否锁止
                                            bcm.setRightDoorLockStatus(rightDoorLockStatus);
                                            bit64 = bit64 >>> 1;
                                            int bcmArmstatus = (byte) (bit64 & 0x01);//
                                            bcm.setBcmArmStatus(bcmArmstatus);
                                            bit64 = bit64 >>> 1;
                                            int bcmEsclpowersupply = (int) (bit64 & 0x03);//
                                            bcm.setBcmEsclPowerSupply(bcmEsclpowersupply);//
                                            bit64 = bit64 >>> 2;
                                            // reserved
                                            bit64 = bit64 >>> 1;
                                            int safetyBeltStatus = (int) (bit64 & 0x03);//安全带是否扣上
                                            bcm.setSafetyBeltStatus(safetyBeltStatus);
                                            bit64 = bit64 >>> 2;
                                            int isLeftDoorClose = (byte) (bit64 & 0x01);//左前门是否关上
                                            bcm.setIsLeftDoorClose(isLeftDoorClose);
                                            bit64 = bit64 >>> 1;
                                            int isRightDoorClose = (byte) (bit64 & 0x01);//右前门是否关上
                                            bcm.setIsRightDoorClose(isRightDoorClose);
                                            bit64 = bit64 >>> 1;
                                            int isEmergecyLightOn = (byte) (bit64 & 0x01);//紧急灯是否开
                                            bcm.setIsEmergecyLightOn(isEmergecyLightOn);
                                            bit64 = bit64 >>> 1;
                                            int wiperStatus = (int) (bit64 & 0x03);//雨刮状态
                                            bcm.setWiperStatus(wiperStatus);
                                            bit64 = bit64 >>> 2;
                                            int isWiperOn = (byte) (bit64 & 0x01);//前雨刮是否开
                                            bcm.setIsWiperStatus(isWiperOn);
                                            bit64 = bit64 >>> 1;
                                            // reserve
                                            bit64 = bit64 >>> 3;
                                            int isFrontHoodOn = (byte) (bit64 & 0x01);//前舱盖是否开
                                            bcm.setIsFrontHoodOn(isFrontHoodOn);
                                            bit64 = bit64 >>> 1;
                                            int isBackDoorOn = (byte) (bit64 & 0x01);//后背门是否开
                                            bcm.setIsBackDoorOn(isBackDoorOn);
                                            bit64 = bit64 >>> 1;
                                            int isHornOn = (byte) (bit64 & 0x01);//喇叭是否开
                                            bcm.setIsHornOn(isHornOn);
                                            bit64 = bit64 >>> 1;
                                            // reserved
                                            bit64 = bit64 >>> 8;
                                            int isKeyVoltageLow = (byte) (bit64 & 0x01);//遥控钥匙电池电量是否低(PEPS指令)
                                            bcm.setIsKeyVoltageLow(isKeyVoltageLow);
                                            bit64 = bit64 >>> 1;
                                            int inbrakeStatus = (int) (bit64 & 0x07);//非法入侵状况
                                            bcm.setIsBrakeStatus(inbrakeStatus);

                                        } else if (canId == (int) 0x18C00501) {//VMS_Info2
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("VMS_Info2[0x18C00501]--->" + ByteBufUtil.hexDump(canBuffer));
                                            bit64 = bit64 >> 16;
                                            int motorStatus = (int) (bit64 & 0x03);//电机当前状态
                                            vms.setMotorStatus(motorStatus);
                                            bit64 = bit64 >> 2;
                                            int isMotorTempHigh = (int) (bit64 & 0x01);//电机温度是否过高
                                            vms.setIsMotorTempHigh(isMotorTempHigh);
                                            bit64 = bit64 >> 1;
                                            int isMotorControlerTempHigh = (int) (bit64 & 0x01);//电机控制器温度是否过高
                                            vms.setIsMotorControlerTempHigh(isMotorControlerTempHigh);
                                            bit64 = bit64 >> 1;
                                            int isMotorControlerErr = (int) (bit64 & 0x01);//电机控制器是否故障
                                            vms.setIsMotorControlerErr(isMotorControlerErr);
                                            bit64 = bit64 >> 1;
                                            int outAlarmInfo = (int) (bit64 & 0x03);//动力输出报警指示
                                            vms.setOutAlarmInfoNumber(outAlarmInfo);
                                        } else if (canId == (int) 0x18C00301) {//VMS_Msg1
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("VMS_Msg1[0x18C00301]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float batteryGroupCurrent = ((float) (bit64 & 0xFFFF) / 10.0f) - 350.0f;//电池组电流
                                            BigDecimal bigDecimal = new BigDecimal(batteryGroupCurrent);
                                            batteryGroupCurrent = bigDecimal.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            vms.setBatteryGroupCurrent(batteryGroupCurrent);

                                            bit64 = bit64 >>> 16;
                                            float batteryGroupVoltage = (float) (bit64 & 0xFF);//电池组电压
                                            vms.setBatteryGroupVoltage(batteryGroupVoltage);
                                            bit64 = bit64 >>> 8;
                                            int leaveBattery = (int) (bit64 & 0xFF);//剩余电量
                                            vms.setLeaveBattery(leaveBattery);
                                            bit64 = bit64 >>> 8;
                                            float speed = (float) (bit64 & 0xFF) * 0.5f;//车速
                                            BigDecimal bigDecimal1 = new BigDecimal(speed);
                                            speed = bigDecimal1.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            vms.setSpeed(speed);
                                            bit64 = bit64 >>> 8;
                                            int motorSysTemp = (int) (bit64 & 0xFF) - 40;//电机系统温度
                                            vms.setMotorSysTemp(motorSysTemp);
                                            bit64 = bit64 >>> 8;
                                            int gearStatus = (int) (bit64 & 0x03);//档位信息
                                            vms.setGearStatus(gearStatus);
                                            bit64 = bit64 >>> 2;
                                            int keyPos = (int) (bit64 & 0x03) & 0xFF;//钥匙位置信息
                                            vms.setKeyPos(keyPos);
                                            bit64 = bit64 >>> 2;
                                            int powerDescStatus = (int) (bit64 & 0x01);//

                                            bit64 = bit64 >>> 1;
                                            int isAirconOpen = (int) (bit64 & 0x01);//空调使能
                                            vms.setIsAirconOpen(isAirconOpen);
                                            bit64 = bit64 >>> 1;
                                            int pepsStatus = (int) (bit64 & 0x01);//PEPS认证状态
                                            vms.setPepsStatus(pepsStatus);
                                            bit64 = bit64 >>> 2;
                                            int isReady = (int) (bit64 & 0xFF);//READY信号
                                            vms.setIsReady(isReady);
                                        } else if (canId == (int) 0x0CF10501) {//
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("[0x0CF10501]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int workType = (int) (bit64 & 0x03);
                                            vms.setWorkType(workType);
                                            bit64 = bit64 >>> 2;
                                            int gear = (int) (bit64 & 0x03);
                                            vms.setGear(gear);
                                            bit64 = bit64 >>> 2;
                                            int brakStatus = (int) (bit64 & 0x03);
                                            vms.setBrakStatus(brakStatus);
                                            bit64 = bit64 >>> 2;
                                            bit64 = bit64 >>> 2;
                                            int deratStatus = (int) (bit64 & 0x03);
                                            vms.setDeratStatus(deratStatus);
                                            bit64 = bit64 >>> 2;
                                            bit64 = bit64 >>> 6;
                                            int keyPosition = (int) (bit64 & 0x03);
                                            vms.setKeyPosition(keyPosition);
                                            bit64 = bit64 >>> 2;
                                            bit64 = bit64 >>> 2;
                                            bit64 = bit64 >>> 12;
                                            int outchargelineConStatus = (int) (bit64 & 0x01);
                                            vms.setOutchargelineConStatus(outchargelineConStatus);
                                            bit64 = bit64 >>> 1;
                                            bit64 = bit64 >>> 1;
                                            bit64 = bit64 >>> 1;
                                            bit64 = bit64 >>> 1;
                                            int tochargeConStatus = (int) (bit64 & 0x01);
                                            vms.setTochargeConStatus(tochargeConStatus);
                                            bit64 = bit64 >>> 1;
                                            bit64 = bit64 >>> 1;
                                            int carType = (int) (bit64 & 0x03);
                                            vms.setCarType(carType);
                                            bit64 = bit64 >>> 2;
                                            int gprsLockCommand = (int) (bit64 & 0x03);
                                            vms.setGprsLockCommand(gprsLockCommand);
                                            bit64 = bit64 >>> 1;
                                            bit64 = bit64 >>> 7;
                                            int vmsSoc = (int) (bit64 & 0xFF);
                                            vms.setVmsSoc(vmsSoc);
                                        } else if (canId == (int) 0x18FF00E0) {//eps EPS_Function
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("EPS_Function[0x18FF00E0]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int errLevel = (int) (bit64 & 0xFF); //EPS 故障等级
                                            eps.setErrLevel(errLevel);
                                            bit64 = bit64 >> 8;
                                            int isWork = (int) (bit64 & 0xFF);//EPS 工作状态
                                            eps.setIsWork(isWork);
                                            bit64 = bit64 >> 8;
                                            float helpMoment = (float) ((bit64 & 0xFFFF)) * 0.1f - 25.0f;//EPS 助力力矩
                                            BigDecimal b1 = new BigDecimal(helpMoment);
                                            helpMoment = b1.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            eps.setHelpMoment(helpMoment);
                                            bit64 = bit64 >> 16;
                                            float electricity = (float) (bit64 & 0xFFFF) * 0.1f;//EPS 电机工作电流
                                            BigDecimal b2 = new BigDecimal(electricity);
                                            electricity = b2.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            eps.setElectricity(electricity);
                                            bit64 = bit64 >> 16;
                                            float voltage = (float) (bit64 & 0xFF) * 0.1f;//电源电压
                                            BigDecimal b3 = new BigDecimal(voltage);
                                            voltage = b3.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            eps.setVoltage(voltage);
                                        } else if (canId == (int) 0x18FF01E0) {//eps EPS_Error
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("EPS_Error[0x18FF01E0]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int isSensorErr = (int) (bit64 & 0x01);//EPS传感器故障
                                            eps.setIsSensorErr(isSensorErr);
                                            bit64 = bit64 >>> 1;
                                            int isCurrentException = (byte) (bit64 & 0x01);//EPS电流异常
                                            eps.setIsCurrentException(isCurrentException);
                                            bit64 = bit64 >>> 1;
                                            int isVoltageHigher = (byte) (bit64 & 0x01);//EPS电压过高
                                            eps.setIsVoltageHigher(isVoltageHigher);
                                            bit64 = bit64 >>> 1;
                                            int isTempHigher = (byte) (bit64 & 0x01);//EPS温度过高
                                            eps.setIsTempHigher(isTempHigher);
                                            bit64 = bit64 >>> 1;
                                            int isVoltageLower = (byte) (bit64 & 0x01);//EPS电压过低
                                            eps.setIsVoltageLower(isVoltageLower);
                                            bit64 = bit64 >>> 1;
                                            int isInitException = (byte) (bit64 & 0x01);//EPS初始化异常
                                            eps.setIsInitException(isInitException);
                                            bit64 = bit64 >>> 1;
                                            int isDriverErr = (byte) (bit64 & 0x01);//EPS电机驱动器故障
                                            eps.setIsDriverErr(isDriverErr);//电机驱动器故障
                                            bit64 = bit64 >>> 1;
                                            int initErr = (byte) (bit64 & 0x01);//电机初始化及轮询故障
                                            eps.setIsMotorInitErr(initErr);
                                            bit64 = bit64 >>> 1;
                                            int angSensorErr = (byte) (bit64 & 0x01);//角度传感器故障
                                            eps.setIsAngleSensorErr(angSensorErr);
                                            bit64 = bit64 >>> 1;
                                            int canEcuErr = (byte) (bit64 & 0x01);//CAN控制器故障
                                            eps.setIsCanCtrlErr(canEcuErr);
                                            bit64 = bit64 >>> 1;
                                            int vspeedSignalEnable = (byte) (bit64 & 0x01);//钥匙位置或车速信号失效
                                            eps.setIsKeyInvalid(vspeedSignalEnable);
                                            bit64 = bit64 >>> 1;
                                            int tempSensorLower = (byte) (bit64 & 0x01);//温度传感器超下限
                                            eps.setIsTempLowerLmt(tempSensorLower);
                                            bit64 = bit64 >>> 1;
                                            int tempSensorHigher = (byte) (bit64 & 0x01);//温度传感器超上限
                                            eps.setIsTempHigher(tempSensorHigher);
                                        } else if (canId == (int) 0x04FF00C8) {//acu ACU_SysSt
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("ACU_SysSt[0x04FF00C8]--->" + ByteBufUtil.hexDump(canBuffer));
                                            bit64 = bit64 >>> 8;
                                            int isCrash = (int) (bit64 & 0x01);//碰撞状态
                                            bit64 = bit64 >>> 1;
                                            int crashPos = (int) (bit64 & 0x7);//碰撞位置
                                            bit64 = bit64 >> 3;
                                            int isGaslightErr = (int) (bit64 & 0x03);//安全气囊故障灯状态

                                        } else if (canId == (int) 0x10FF01DF) {//adas ADAS_Msg1
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("ADAS_Msg1[0x10FF01DF]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int leftLaneDetected = (int) (bit64 & 0x01);//左车道检测
                                            adas.setLeftLaneDetected(leftLaneDetected);
                                            bit64 = bit64 >> 1;
                                            int laneDepartureLeft = (int) (bit64 & 0x01);//车道偏离
                                            adas.setLaneDepartureLeft(laneDepartureLeft);
                                            bit64 = bit64 >> 1;
                                            bit64 = bit64 >> 2;
                                            int rightLaneDetected = (int) (bit64 & 0x01);//右车道检测
                                            adas.setRightLaneDetected(rightLaneDetected);
                                            bit64 = bit64 >> 1;
                                            int laneDepartureRight = (int) (bit64 & 0x01);//车道未偏离
                                            adas.setLaneDpartureRight(laneDepartureRight);
                                            bit64 = bit64 >> 1;
                                            bit64 = bit64 >> 2;
                                            int vehicleDecectResult = (int) (bit64 & 0x01);//车道检测结果
                                            adas.setVehicleDecectResult(vehicleDecectResult);
                                            bit64 = bit64 >> 4;
                                            bit64 = bit64 >> 4;
                                            int crashTime = (int) (bit64 & 0xFF);//碰撞时间
                                            adas.setCrashTime(crashTime);
                                            bit64 = bit64 >> 8;
                                            bit64 = bit64 >> 8;
                                            int error = (int) (bit64 & 0xFF);//错误信息
                                            adas.setErrorInfo(error);
                                            bit64 = bit64 >> 8;
                                            int invalidInfo = (int) (bit64 & 0xFF);//无效信息
                                            adas.setInvalidInfo(invalidInfo);
                                        } else if (canId == (int) 0x18C0EFF4) {//BMS_GPRS_msg1
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BMS_GPRS_msg1[0x18C0EFF4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float totalVoltage = (float) (bit64 & 0xFFFF);//总电压
                                            bms.setTotalVoltage(totalVoltage);
                                            bit64 = bit64 >>> 16;
                                            float totalCurrent = (float) (bit64 & 0xFFFF) * 0.1f - 350.0f;
                                            BigDecimal b1 = new BigDecimal(totalCurrent);
                                            totalCurrent = b1.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();//总电流
                                            bms.setTotalCurrent(totalCurrent);

                                            bit64 = bit64 >>> 16;
                                            int isChargerConnected = (int) (bit64 & 0x01);//外接充电线连接状态
                                            bms.setIsChargerConnected(isChargerConnected);
                                            bit64 = bit64 >>> 1;
                                            int cpSignal = (int) (bit64 & 0x01);//cp信号
                                            bms.setCpSignal(cpSignal);
                                            bit64 = bit64 >>> 1;
                                            int ksStatus = (int) (bit64 & 0x01);//总负接触器KS状态
                                            bms.setKsStatus(ksStatus);
                                            bit64 = bit64 >>> 1;
                                            int s2Status = (int) (bit64 & 0x01);//
                                            bms.setS2Status(s2Status);
                                            bit64 = bit64 >>> 1;
                                            int isConnectCharger = (int) (bit64 & 0x01);//与充电机通讯状态
                                            bms.setIsConnectCharger(isConnectCharger);
                                            bit64 = bit64 >>> 1;
                                            int isBatteryGroupBalance = (int) (bit64 & 0x01);//电池包均衡状态
                                            bms.setIsBatteryGroupBalance(isBatteryGroupBalance);
                                            bit64 = bit64 >>> 1;
                                            int fanStatus = (int) (bit64 & 0x01);//
                                            bms.setColdFanStatus(fanStatus);

                                            bit64 = bit64 >>> 1;
                                            //reserverd
                                            bit64 = bit64 >>> 1;
                                            int soc = (int) (bit64 & 0xFF);//电池组当前的SOC
                                            bms.setSoc(soc);
                                            bit64 = bit64 >>> 8;
                                            int batteryGroupStatus = (int) (bit64 & 0x03);//电池组当前状态
                                            bms.setBatteryGroupStatus(batteryGroupStatus);
                                            bit64 = bit64 >>> 2;
                                            int errLevel = (int) (bit64 & 0x07);//
                                            bms.setErrorLevel(errLevel);
                                            bit64 = bit64 >>> 3;
                                            int batteryAlarmWarn = (int) (bit64 & 0x01);//
                                            bms.setBatteryAlarmIndication(batteryAlarmWarn);
                                            bit64 = bit64 >>> 1;
                                            int descPowerLevel = (int) (bit64 & 0x03);//
                                            bms.setDescPowerLevel(descPowerLevel);
                                            bit64 = bit64 >>> 2;
                                            // reserved
                                            bit64 = bit64 >>> 6;
                                            int isInsuLowest = (int) (bit64 & 0x01);//绝缘超低
                                            bms.setIsInsuLowest(isInsuLowest);
                                        } else if (canId == (int) 0x18C0EEF4) { //BmsMsg2
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BmsMsg2[0x18C0EEF4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float voltageHighest = (float) ((bit64 & 0xFFFF) * 0.001f);
                                            BigDecimal b1 = new BigDecimal(voltageHighest);
                                            voltageHighest = b1.setScale(3, BigDecimal.ROUND_HALF_UP).floatValue();//最高单体电压
                                            bms.setVoltageHighest(voltageHighest);
                                            bit64 = bit64 >> 16;

                                            int voltageHighestNo = (int) (bit64 & 0xFF);//最高单体电池号
                                            bit64 = bit64 >> 8;
                                            bms.setVoltageHighestNo(voltageHighestNo);

                                            float voltageLowest = (float) ((bit64 & 0xFFFF) * 0.001f);//最低单体电压
                                            BigDecimal b2 = new BigDecimal(voltageLowest);
                                            voltageLowest = b1.setScale(3, BigDecimal.ROUND_HALF_UP).floatValue();
                                            bms.setVoltageLowest(voltageLowest);

                                            bit64 = bit64 >> 16;
                                            int voltageLowestNo = (int) (bit64 & 0xFF);//最低单体电池号
                                            bms.setVoltageHighestNo(voltageHighestNo);

                                            bit64 = bit64 >> 8;
                                            int tempHighest = (int) (bit64 & 0xFF) - 40;//最高温度点温度
                                            bms.setTempHighest(tempHighest);

                                            bit64 = bit64 >> 8;
                                            int tempHighestNo = (int) (bit64 & 0xFF);//最高温度点电池号
                                            bms.setTempHighestNo(tempHighestNo);
                                        } else if (canId == (int) 0x10C000F4) {//单体电压-start-1
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("单体电压[0x10C000F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float voltage1 = (float) ((bit64 & 0x1FF) * 0.01f);//1#单体电池电压
                                            voltage1 = BigDecimal.valueOf(voltage1).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[0] = voltage1;
                                            bit64 = bit64 >> 9;
                                            float voltage2 = (float) ((bit64 & 0x1FF) * 0.01f);//2#单体电池电压
                                            voltage2 = BigDecimal.valueOf(voltage2).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[1] = voltage2;
                                            bit64 = bit64 >> 9;
                                            float voltage3 = (float) ((bit64 & 0x1FF) * 0.01f);//3#单体电池电压
                                            voltage3 = BigDecimal.valueOf(voltage3).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[2] = voltage3;
                                            bit64 = bit64 >> 9;
                                            float voltage4 = (float) ((bit64 & 0x1FF) * 0.01f);//4#单体电池电压
                                            voltage4 = BigDecimal.valueOf(voltage4).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[3] = voltage4;
                                            bit64 = bit64 >> 9;
                                            float voltage5 = (float) ((bit64 & 0x1FF) * 0.01f);//5#单体电池电压
                                            voltage5 = BigDecimal.valueOf(voltage5).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[4] = voltage5;
                                            bit64 = bit64 >> 9;
                                            float voltage6 = (float) ((bit64 & 0x1FF) * 0.01f);//6#单体电池电压
                                            voltage6 = BigDecimal.valueOf(voltage6).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[5] = voltage6;
                                            bit64 = bit64 >> 9;
                                            float voltage7 = (float) ((bit64 & 0x1FF) * 0.01f);//7#单体电池电压
                                            voltage7 = BigDecimal.valueOf(voltage7).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[6] = voltage7;
                                        } else if (canId == (int) 0x14C000F4) {
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("单体电压[0x14C000F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float voltage8 = (float) ((bit64 & 0x1FF) * 0.01f);//8#单体电池电压
                                            voltage8 = BigDecimal.valueOf(voltage8).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[7] = voltage8;
                                            bit64 = bit64 >> 9;
                                            float voltage9 = (float) ((bit64 & 0x1FF) * 0.01f);//9#单体电池电压
                                            voltage9 = BigDecimal.valueOf(voltage9).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[8] = voltage9;
                                            bit64 = bit64 >> 9;
                                            float voltage10 = (float) ((bit64 & 0x1FF) * 0.01f);//10#单体电池电压
                                            voltage10 = BigDecimal.valueOf(voltage10).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[9] = voltage10;
                                            bit64 = bit64 >> 9;
                                            float voltage11 = (float) ((bit64 & 0x1FF) * 0.01f);//11#单体电池电压
                                            voltage11 = BigDecimal.valueOf(voltage11).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[10] = voltage11;
                                            bit64 = bit64 >> 9;
                                            float voltage12 = (float) ((bit64 & 0x1FF) * 0.01f);//12#单体电池电压
                                            voltage12 = BigDecimal.valueOf(voltage12).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[11] = voltage12;
                                            bit64 = bit64 >> 9;
                                            float voltage13 = (float) ((bit64 & 0x1FF) * 0.01f);//13#单体电池电压
                                            voltage13 = BigDecimal.valueOf(voltage13).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[12] = voltage13;
                                            bit64 = bit64 >> 9;
                                            float voltage14 = (float) ((bit64 & 0x1FF) * 0.01f);//14#单体电池电压
                                            voltage14 = BigDecimal.valueOf(voltage14).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[13] = voltage14;
                                        } else if (canId == (int) 0x18C000F4) {
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("单体电压[0x18C000F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float voltage15 = (float) ((bit64 & 0x1FF) * 0.01f);//15#单体电池电压
                                            voltage15 = BigDecimal.valueOf(voltage15).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[14] = voltage15;
                                            bit64 = bit64 >> 9;
                                            float voltage16 = (float) ((bit64 & 0x1FF) * 0.01f);//16#单体电池电压
                                            voltage16 = BigDecimal.valueOf(voltage16).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[15] = voltage16;
                                            bit64 = bit64 >> 9;
                                            float voltage17 = (float) ((bit64 & 0x1FF) * 0.01f);//17#单体电池电压
                                            voltage17 = BigDecimal.valueOf(voltage17).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[16] = voltage17;
                                            bit64 = bit64 >> 9;
                                            float voltage18 = (float) ((bit64 & 0x1FF) * 0.01f);//18#单体电池电压
                                            voltage18 = BigDecimal.valueOf(voltage18).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[17] = voltage18;
                                            bit64 = bit64 >> 9;
                                            float voltage19 = (float) ((bit64 & 0x1FF) * 0.01f);//19#单体电池电压
                                            voltage19 = BigDecimal.valueOf(voltage19).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[18] = voltage19;
                                            bit64 = bit64 >> 9;
                                            float voltage20 = (float) ((bit64 & 0x1FF) * 0.01f);//20#单体电池电压
                                            voltage20 = BigDecimal.valueOf(voltage20).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[19] = voltage20;
                                            bit64 = bit64 >> 9;
                                            float voltage21 = (float) ((bit64 & 0x1FF) * 0.01f);//21#单体电池电压
                                            voltage21 = BigDecimal.valueOf(voltage21).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[20] = voltage21;
                                        } else if (canId == (int) 0x1CC000F4) {
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("单体电压[0x1CC000F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float voltage22 = (float) ((bit64 & 0x1FF) * 0.01f);//22#单体电池电压
                                            voltage22 = BigDecimal.valueOf(voltage22).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[21] = voltage22;
                                            bit64 = bit64 >> 9;
                                            float voltage23 = (float) ((bit64 & 0x1FF) * 0.01f);//23#单体电池电压
                                            voltage23 = BigDecimal.valueOf(voltage23).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[22] = voltage23;
                                            bit64 = bit64 >> 9;
                                            float voltage24 = (float) ((bit64 & 0x1FF) * 0.01f);//24#单体电池电压
                                            voltage24 = BigDecimal.valueOf(voltage24).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[23] = voltage24;
                                            bit64 = bit64 >> 9;
                                            float voltage25 = (float) ((bit64 & 0x1FF) * 0.01f);//25#单体电池电压
                                            voltage25 = BigDecimal.valueOf(voltage25).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[24] = voltage25;
                                            bit64 = bit64 >> 9;
                                            float voltage26 = (float) ((bit64 & 0x1FF) * 0.01f);//26#单体电池电压
                                            voltage26 = BigDecimal.valueOf(voltage26).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[25] = voltage26;
                                            bit64 = bit64 >> 9;
                                            float voltage27 = (float) ((bit64 & 0x1FF) * 0.01f);//27#单体电池电压
                                            voltage27 = BigDecimal.valueOf(voltage27).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[26] = voltage27;
                                            bit64 = bit64 >> 9;
                                            float voltage28 = (float) ((bit64 & 0x1FF) * 0.01f);//28#单体电池电压
                                            voltage28 = BigDecimal.valueOf(voltage28).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[27] = voltage28;
                                        } else if (canId == (int) 0x1CC007F4) {
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("单体电压[0x1CC007F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float voltage29 = (float) ((bit64 & 0x1FF) * 0.01f);//29#单体电池电压
                                            voltage29 = BigDecimal.valueOf(voltage29).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[28] = voltage29;
                                            bit64 = bit64 >> 9;
                                            float voltage30 = (float) ((bit64 & 0x1FF) * 0.01f);//30#单体电池电压
                                            voltage30 = BigDecimal.valueOf(voltage30).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[29] = voltage30;
                                            bit64 = bit64 >> 9;
                                            float voltage31 = (float) ((bit64 & 0x1FF) * 0.01f);//31#单体电池电压
                                            voltage31 = BigDecimal.valueOf(voltage31).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[30] = voltage31;
                                            bit64 = bit64 >> 9;
                                            float voltage32 = (float) ((bit64 & 0x1FF) * 0.01f);//32#单体电池电压
                                            voltage32 = BigDecimal.valueOf(voltage32).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[31] = voltage32;
                                            bit64 = bit64 >> 9;
                                            float voltage33 = (float) ((bit64 & 0x1FF) * 0.01f);//33#单体电池电压
                                            voltage33 = BigDecimal.valueOf(voltage33).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[32] = voltage33;
                                            bit64 = bit64 >> 9;
                                            float voltage34 = (float) ((bit64 & 0x1FF) * 0.01f);//34#单体电池电压
                                            voltage34 = BigDecimal.valueOf(voltage34).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[33] = voltage34;
                                            bit64 = bit64 >> 9;
                                            float voltage35 = (float) ((bit64 & 0x1FF) * 0.01f);//35#单体电池电压
                                            voltage35 = BigDecimal.valueOf(voltage35).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[34] = voltage35;
                                        } else if (canId == (int) 0x1CC008F4) {//单体电压-end-6
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("单体电压[0x1CC008F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float voltage36 = (float) ((bit64 & 0x1FF) * 0.01f);//36#单体电池电压
                                            voltage36 = BigDecimal.valueOf(voltage36).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[35] = voltage36;
                                            bit64 = bit64 >> 9;
                                            float voltage37 = (float) ((bit64 & 0x1FF) * 0.01f);//37#单体电池电压
                                            voltage37 = BigDecimal.valueOf(voltage37).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[36] = voltage37;
                                            bit64 = bit64 >> 9;
                                            float voltage38 = (float) ((bit64 & 0x1FF) * 0.01f);//38#单体电池电压
                                            voltage38 = BigDecimal.valueOf(voltage38).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[37] = voltage38;
                                            bit64 = bit64 >> 9;
                                            float voltage39 = (float) ((bit64 & 0x1FF) * 0.01f);//39#单体电池电压
                                            voltage39 = BigDecimal.valueOf(voltage39).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[38] = voltage39;
                                            bit64 = bit64 >> 9;
                                            float voltage40 = (float) ((bit64 & 0x1FF) * 0.01f);//40#单体电池电压
                                            voltage40 = BigDecimal.valueOf(voltage40).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[39] = voltage40;
                                            bit64 = bit64 >> 9;
                                            float voltage41 = (float) ((bit64 & 0x1FF) * 0.01f);//41#单体电池电压
                                            voltage41 = BigDecimal.valueOf(voltage41).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[40] = voltage41;
                                            bit64 = bit64 >> 9;
                                            float voltage42 = (float) ((bit64 & 0x1FF) * 0.01f);//42#单体电池电压
                                            voltage42 = BigDecimal.valueOf(voltage42).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[41] = voltage42;
                                        } else if (canId == (int) 0x18FF05F4) {//BMS_Error
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BMS_Error[0x18FF05F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int sellVoltageHighestChargerL4 = (int) (bit64 & 0x01);//单体电压超高-充电-4级
                                            bms.setSellVolHighestChargerl4(sellVoltageHighestChargerL4);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageHighestFbL3 = (int) (bit64 & 0x01);//单体电压超高-回馈-3级
                                            bms.setSellVolHighestFbl3(sellVoltageHighestFbL3);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageHighestL3 = (int) (bit64 & 0x01);//单体电压超高-3级
                                            bms.setSellVolHighestL3(sellVoltageHighestL3);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageHighestChargerL4 = (int) (bit64 & 0x01);//总电压超高-充电-4级
                                            bms.setTotalVolHighestChargerl4(totalVoltageHighestChargerL4);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageHighestFbL3 = (int) (bit64 & 0x01);//总电压超高-回馈-3级
                                            bms.setTotalVolHighestFbl3(totalVoltageHighestFbL3);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageHighestL3 = (int) (bit64 & 0x01);//总电压超高-3级
                                            bms.setTotalVolHighestl3(totalVoltageHighestL3);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageLowerL1 = (int) (bit64 & 0x01);//单体电压过低-1级降功率
                                            bms.setSellVolLowerl1(sellVoltageLowerL1);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageLowerL2 = (int) (bit64 & 0x01);//单体电压过低-2级降功率
                                            bms.setSellVolLowerl2(sellVoltageLowerL2);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageLowerL3 = (int) (bit64 & 0x01);//单体电压过低-3级降功率
                                            bms.setSellVolLowerl3(sellVoltageLowerL3);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageLowerL1 = (int) (bit64 & 0x01);//总电压过低-1级降功率
                                            bms.setTotalVolLowerl1(totalVoltageLowerL1);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageLowerL2 = (int) (bit64 & 0x01);//总电压过低-2级降功率
                                            bms.setTotalVolLowerl2(totalVoltageLowerL2);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageLowerL3 = (int) (bit64 & 0x01);//总电压过低-3级降功率
                                            bms.setTotalVolLowerl3(totalVoltageHighestL3);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageLowestL3 = (int) (bit64 & 0x01);//单体电压超低-3级
                                            bms.setSellVolLowestl3(sellVoltageLowestL3);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageLowestL4 = (int) (bit64 & 0x01);//单体电压超低-4级
                                            bms.setSellVolLowestl4(sellVoltageLowestL4);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageLowestCharger = (int) (bit64 & 0x01);//单体电压超低-充电
                                            bms.setSellVolLowestCharger(sellVoltageLowestCharger);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageLowestL3 = (int) (bit64 & 0x01);//总电压超低-3级
                                            bms.setTotalVolLowerl3(totalVoltageHighestL3);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageLowestL4 = (int) (bit64 & 0x01);//总电压超低-4级
                                            bms.setTotalVolLowestl4(totalVoltageLowestL4);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageLowestCharger = (int) (bit64 & 0x01);//总电压超低-充电
                                            bms.setTotalVolLowestCharger(totalVoltageLowestCharger);
                                            bit64 = bit64 >> 1;
                                            int voltagePlusBiggerL1 = (int) (bit64 & 0x01);//压差过大-1级降功率
                                            bms.setVolPlusBiggerl1(voltagePlusBiggerL1);
                                            bit64 = bit64 >> 1;
                                            int voltagePlusBiggerL2 = (int) (bit64 & 0x01);//压差过大-2级降功率
                                            bms.setVolPlusBiggerl2(voltagePlusBiggerL2);
                                            bit64 = bit64 >> 1;
                                            int voltagePlusBiggerL3 = (int) (bit64 & 0x01);//压差过大-3级降功率
                                            bms.setVolPlusBiggerl3(voltagePlusBiggerL3);
                                            bit64 = bit64 >> 1;
                                            int socLowerL1 = (int) (bit64 & 0x01);//SOC过低-1级降功率
                                            bms.setSocLowerl1(socLowerL1);
                                            bit64 = bit64 >> 1;
                                            int socLowerL2 = (int) (bit64 & 0x01);//SOC过低-2级降功率
                                            bms.setSocLowerl2(socLowerL2);
                                            bit64 = bit64 >> 1;
                                            int socLowerL3 = (int) (bit64 & 0x01);//SOC过低-3级降功率
                                            bms.setSocLowerl3(socLowerL3);
                                            bit64 = bit64 >> 1;
                                            int dischargerCurrentBiggerL1 = (int) (bit64 & 0x01);//放电电流过大-1级降功率
                                            bms.setDischargerCurrentBiggerl1(dischargerCurrentBiggerL1);
                                            bit64 = bit64 >> 1;
                                            int dischargerCurrentBiggerL2 = (int) (bit64 & 0x01);//放电电流过大-2级降功率
                                            bms.setDischargerCurrentBiggerl2(dischargerCurrentBiggerL2);
                                            bit64 = bit64 >> 1;
                                            int dischargerCurrentBiggerL3 = (int) (bit64 & 0x01);//放电电流过大-3级降功率
                                            bms.setDischargerCurrentBiggerl3(dischargerCurrentBiggerL3);
                                            bit64 = bit64 >> 1;
                                            int dischargerCurrentBiggestL3 = (int) (bit64 & 0x01);//放电电流超大-3级
                                            bms.setDischargerCurrentBiggestl3(dischargerCurrentBiggestL3);
                                            bit64 = bit64 >> 1;
                                            int chargerCurrentBiggestL3 = (int) (bit64 & 0x01);//充电电流超大-3级
                                            bms.setChargerCurrentBiggestl3(chargerCurrentBiggestL3);
                                            bit64 = bit64 >> 1;
                                            int chargerCurrentBiggestL4 = (int) (bit64 & 0x01);//充电电流超大-4级
                                            bms.setChargerCurrentBiggestl4(chargerCurrentBiggestL4);
                                            bit64 = bit64 >> 1;
                                            int feedBackCurrentBiggestL3 = (int) (bit64 & 0x01);//回馈电流超大-3级
                                            bms.setFeedbackCurrentBiggestl3(feedBackCurrentBiggestL3);
                                            bit64 = bit64 >> 1;
                                            int feedBackCurrentBiggestL4 = (int) (bit64 & 0x01);//回馈电流超大-4级
                                            bms.setFeedbackCurrentBiggestl4(feedBackCurrentBiggestL4);
                                            bit64 = bit64 >> 1;
                                            int tempratureHigherL1 = (int) (bit64 & 0x01);//温度过高-1级降功率
                                            bms.setTempratureHigherl1(tempratureHigherL1);
                                            bit64 = bit64 >> 1;
                                            int tempratureHigherL2 = (int) (bit64 & 0x01);//温度过高-2级降功率
                                            bms.setTempratureHigherl2(tempratureHigherL2);
                                            bit64 = bit64 >> 1;
                                            int tempratureHigherL3 = (int) (bit64 & 0x01);//温度过高-3级降功率
                                            bms.setTempratureHigherl3(tempratureHigherL3);
                                            bit64 = bit64 >> 1;
                                            int tempratureHighestL3 = (int) (bit64 & 0x01);//温度超高-3级
                                            bms.setTempratureHigherl3(tempratureHighestL3);
                                            bit64 = bit64 >> 1;
                                            int tempratureHighestL4 = (int) (bit64 & 0x01);//温度超高-4级
                                            bms.setTempratureHighestl4(tempratureHighestL4);
                                            bit64 = bit64 >> 1;
                                            int heatMoTempratureHighest = (int) (bit64 & 0x01);//加热膜温度超高
                                            bms.setHeatMoTempratureHighest(heatMoTempratureHighest);
                                            bit64 = bit64 >> 1;
                                            int tempratureLowerL1 = (int) (bit64 & 0x01);//温度过低-1级降功率
                                            bms.setTempLowerl1(tempratureLowerL1);
                                            bit64 = bit64 >> 1;
                                            int tempratureLowerL2 = (int) (bit64 & 0x01);//温度过低-2级降功率
                                            bms.setTempLowerl2(tempratureHigherL2);
                                            bit64 = bit64 >> 1;
                                            int tempratureLowerL3 = (int) (bit64 & 0x01);//温度过低-3级降功率
                                            bms.setTempLowerl3(tempratureLowerL3);
                                            bit64 = bit64 >> 1;
                                            int tempratureLowestL3 = (int) (bit64 & 0x01);//温度超低-3级
                                            bms.setTempLowestl3(tempratureHighestL3);
                                            bit64 = bit64 >> 1;
                                            int tempraturePlusHigherL1 = (int) (bit64 & 0x01);//温差过高-1级降功率
                                            bms.setTempPlusHigherl1(tempraturePlusHigherL1);
                                            bit64 = bit64 >> 1;
                                            int tempraturePlusHigherL2 = (int) (bit64 & 0x01);//温差过高-2级降功率
                                            bms.setTempPlusHigherl2(tempraturePlusHigherL2);
                                            bit64 = bit64 >> 1;
                                            int tempraturePlusHigherL3 = (int) (bit64 & 0x01);//温差过高-3级降功率
                                            bms.setTempPlusHigherl3(tempraturePlusHigherL3);
                                            bit64 = bit64 >> 1;
                                            int tempratureRiseSpeedBiggerL2 = (int) (bit64 & 0x01);//温升速率过高-2级降功率
                                            bms.setTempRiseSpeedBiggerl2(tempratureRiseSpeedBiggerL2);
                                            bit64 = bit64 >> 1;
                                            int tempratureRiseSpeedBiggestL4 = (int) (bit64 & 0x01);//温升速率超高-4级
                                            bms.setTempRiseSpeedBiggestl4(tempratureRiseSpeedBiggestL4);
                                            bit64 = bit64 >> 1;
                                            int insuLowL1 = (int) (bit64 & 0x01);//绝缘过低-1级
                                            bms.setInsuLowl1(insuLowL1);
                                            bit64 = bit64 >> 1;
                                            int insuLowL2 = (int) (bit64 & 0x01);//绝缘过低-2级降功率
                                            bms.setInsuLowl2(insuLowL2);
                                            bit64 = bit64 >> 1;
                                            int insuLowL4 = (int) (bit64 & 0x01);//绝缘超低-4级
                                            bms.setInsuLowl4(insuLowL4);
                                            bit64 = bit64 >> 1;
                                            int chargeTimeLong = (int) (bit64 & 0x01);//充电时间超长
                                            bms.setChargeTimeLong(chargeTimeLong);
                                            bit64 = bit64 >> 1;
                                            int heatTimeLong = (int) (bit64 & 0x01);//加热时间超长
                                            bms.setHeatTimeLong(heatTimeLong);
                                            bit64 = bit64 >> 1;
                                            int bmsSysErr = (int) (bit64 & 0x01);//BMS系统故障
                                            bms.setBmsSysErr(bmsSysErr);
                                            bit64 = bit64 >> 1;
                                            int chargerNetErr = (int) (bit64 & 0x01);//与充电机通讯故障
                                            bms.setChargerNetErr(chargerNetErr);
                                            bit64 = bit64 >> 1;
                                            int voltageDisconnectL4 = (int) (bit64 & 0x01);//电压采集断开-4级
                                            bms.setVolDisconnectl4(voltageDisconnectL4);
                                            bit64 = bit64 >> 1;
                                            int voltageDisconnectL2 = (int) (bit64 & 0x01);//电压采集断开-2级降功率
                                            bms.setVolDisconnectl2(voltageDisconnectL2);
                                            bit64 = bit64 >> 1;
                                            int tempratureDisconnectL4 = (int) (bit64 & 0x01);//温度采集断开-4级
                                            bms.setTempDisconnectl4(tempratureDisconnectL4);
                                            bit64 = bit64 >> 1;
                                            int tempratureDisconnectL2 = (int) (bit64 & 0x01);//温度采集断开-2级降功率
                                            bms.setTempDisconnectl2(tempratureDisconnectL2);
                                            bit64 = bit64 >> 1;
                                            int heatErr = (int) (bit64 & 0x01);//加热故障
                                            bms.setHeatErr(heatErr);
                                            bit64 = bit64 >> 1;
                                            int negErrClose = (int) (bit64 & 0x01);//负极接触器故障：不能闭合
                                            bms.setNegErrClose(negErrClose);
                                            bit64 = bit64 >> 1;
                                            int negErrPaste = (int) (bit64 & 0x01);//负极接触器故障：粘连
                                            bms.setNegErrPaste(negErrPaste);
                                            bit64 = bit64 >> 1;
                                        } else if (canId == (int) 0x04C000F4) {
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("探头温度[0x04C000F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int temprature1 = (int) (bit64 & 0xFF) - 40;//1#探头温度

                                            tempratureArray[0] = temprature1;
                                            bit64 = bit64 >> 8;
                                            int temprature2 = (int) (bit64 & 0xFF) - 40;//2#探头温度
                                            tempratureArray[1] = temprature2;
                                            bit64 = bit64 >> 8;
                                            int temprature3 = (int) (bit64 & 0xFF) - 40;//3#探头温度
                                            tempratureArray[2] = temprature3;
                                            bit64 = bit64 >> 8;
                                            int temprature4 = (int) (bit64 & 0xFF) - 40;//4#探头温度
                                            tempratureArray[3] = temprature4;
                                            bit64 = bit64 >> 8;
                                            int temprature5 = (int) (bit64 & 0xFF) - 40;//5#探头温度
                                            tempratureArray[4] = temprature5;
                                            bit64 = bit64 >> 8;
                                            int temprature6 = (int) (bit64 & 0xFF) - 40;//6#探头温度
                                            tempratureArray[5] = temprature6;
                                            bit64 = bit64 >> 8;
                                            int temprature7 = (int) (bit64 & 0xFF) - 40;//7#探头温度
                                            tempratureArray[6] = temprature7;
                                            bit64 = bit64 >> 8;
                                            int temprature8 = (int) (bit64 & 0xFF) - 40;//8#探头温度
                                            tempratureArray[7] = temprature8;
                                        } else if (canId == (int) 0x08C000F4) {
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("探头温度[0x08C000F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int temprature9 = (int) (bit64 & 0xFF) - 40;//9#探头温度
                                            tempratureArray[8] = temprature9;
                                            bit64 = bit64 >>> 8;
                                            int temprature10 = (int) (bit64 & 0xFF) - 40;//10#探头温度
                                            tempratureArray[9] = temprature10;
                                            bit64 = bit64 >>> 8;
                                            int temprature11 = (int) (bit64 & 0xFF) - 40;//11#探头温度
                                            tempratureArray[10] = temprature11;
                                            bit64 = bit64 >>> 8;
                                            int temprature12 = (int) (bit64 & 0xFF) - 40;//12#探头温度
                                            tempratureArray[11] = temprature12;
                                            bit64 = bit64 >>> 32;
                                            int bmsError = (int) (bit64 & 0xFF);//BMS故障码
                                            bms.setBmsError(bmsError);

                                        } else if (canId == (int) 0x1806E5F4) {//BMS_charger
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BMS_charger[0x1806E5F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float alowableVoltage = (float) ((bit64 & 0xFFFF) * 0.1f);//最高允许充电端电压
                                            alowableVoltage = BigDecimal.valueOf(alowableVoltage).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            bms.setAlowableVoltage(alowableVoltage);
                                            bit64 = bit64 >>> 16;
                                            float alowableCurrent = (float) ((bit64 & 0xFFFF) * 0.1f);//最高允许充电电流
                                            alowableCurrent = BigDecimal.valueOf(alowableCurrent).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            bms.setAlowableCurrent(alowableCurrent);
                                            bit64 = bit64 >>> 16;
                                            int isableCharge = (int) (bit64 & 0xFF);//

                                            bit64 = bit64 >>> 8;
                                            int loadType = (int) (bit64 & 0x01);//负载类型
                                            bms.setLoadType(loadType);
                                            bit64 = bit64 >>> 1;
                                            int heaterStatus = (int) (bit64 & 0x01);//加热继电器状态
                                            bms.setHeaterStatus(heaterStatus);
                                            bit64 = bit64 >>> 1;
                                            // reserve
                                            bit64 = bit64 >>> 6;
                                            int chargerCount = (int) (bit64 & 0xFFF);//充电次数
                                            bms.setChargerCount(chargerCount);
                                        } else if (canId == (int) 0x18FF01F4) {//BMS_power
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BMS_power[0x18FF01F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int discharge10sPower = (int) (bit64 & 0xFFFF);//动力电池包 10s 最大充电功率
                                            bms.setDischarge10SPower(discharge10sPower);
                                            bit64 = bit64 >> 16;
                                            int discharge30sPower = (int) (bit64 & 0xFFFF);//动力电池包 30s 最大放电功率\
                                            bms.setDischarge30SPower(discharge30sPower);
                                            bit64 = bit64 >> 16;
                                            int dischargeMaximumPower = (int) (bit64 & 0xFFFF);//动力电池包持续最大放电功率
                                            bms.setDischargeMaximumPower(dischargeMaximumPower);
                                            bit64 = bit64 >> 16;
                                            int dischargeMaximumCurrent = (int) (bit64 & 0xFFFF);//动力电池包最大放电电流限值
                                            bms.setDischargeMaximumCurrent(dischargeMaximumCurrent);
                                            bit64 = bit64 >> 16;
                                        } else if (canId == (int) 0x18FF02F4) {//BMS_chargerpower
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BMS_chargerpower[0x18FF02F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int charge10sPower = (int) (bit64 & 0xFFFF);//动力电池包 10s 最大充电功率
                                            bms.setCharge10SPower(charge10sPower);
                                            bit64 = bit64 >> 16;
                                            int charge30sPower = (int) (bit64 & 0xFFFF);//动力电池包 30s 最大充电功率
                                            bms.setCharge30SPower(charge30sPower);
                                            bit64 = bit64 >> 16;
                                            int chargeMaximumPower = (int) (bit64 & 0xFFFF);//动力电池包持续最大充电功率\
                                            bms.setChargeMaximumPower(chargeMaximumPower);
                                            bit64 = bit64 >> 16;
                                            int chargeMaximumCurrent = (int) (bit64 & 0xFFFF) - 350;//动力电池包最大充电电流限值
                                            bms.setChargeMaximumCurrent(chargeMaximumCurrent);
                                            bit64 = bit64 >> 16;
                                        } else if (canId == (int) 0x0CF11F05) {// MC_VMS1
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("MC_VMS1[0x0CF11F05]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int muStatus = (int) (bit64 & 0x03);//电机控制器状态
                                            mc.setMuStatus(muStatus);
                                            bit64 = bit64 >> 2;
                                            int runStatus = (int) (bit64 & 0x03);//电机控制器工作状态
                                            mc.setRunStatus(runStatus);
                                            bit64 = bit64 >> 2;
                                            int temStatus = (int) (bit64 & 0x03);//温度状态
                                            mc.setTemStatus(temStatus);
                                            bit64 = bit64 >> 2;
                                            int voltageStatus = (int) (bit64 & 0x03);//母线电压状态
                                            mc.setVoltageStatus(voltageStatus);
                                            bit64 = bit64 >> 2;
                                            float voltageRange = (float) (bit64 & 0xFF) * 0.5f;//母线电压
                                            voltageRange = BigDecimal.valueOf(voltageRange).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            mc.setVoltageRange(voltageRange);
                                            bit64 = bit64 >> 8;
                                            int motorTemprature = (int) (bit64 & 0xFF) - 40;//电机温度
                                            mc.setMotorTemprature(motorTemprature);
                                            bit64 = bit64 >> 8;
                                            int mcTemprature = (int) (bit64 & 0xFF) - 40;//控制器温度
                                            mc.setMcTemprature(mcTemprature);
                                            bit64 = bit64 >> 8;
                                            int motorRpm = (int) (bit64 & 0xFFFF);//电机转速
                                            mc.setMotorRpm(motorRpm);
                                            bit64 = bit64 >> 16;
                                            float motorCurrent = (float) (bit64 & 0xFFFF) * 0.5f;//电机相电流
                                            motorCurrent = BigDecimal.valueOf(motorCurrent).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            mc.setMotorCurrent(motorCurrent);
                                        } else if (canId == (int) 0x0CF12F05) {// MC_Info1
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("MC_Info1[0x0CF12F05]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int aprRate = (int) (bit64 & 0xFF);//加速踏板开度
                                            mc.setAprRate(aprRate);
                                            bit64 = bit64 >>> 8;
                                            int mcNm = (int) (bit64 & 0xFF) - 120;//电机控制器当前估计扭矩
                                            mc.setMcNm((float) mcNm);
                                            bit64 = bit64 >>> 8;
                                            int busCurrent = (int) (bit64 & 0xFFFF) - 350;//母线电流
                                            mc.setBusCurrent((float) busCurrent);
                                            bit64 = bit64 >>> 16;
                                            int brakeRate = (int) (bit64 & 0xFF);//制动踏板开度
                                            mc.setBrakeRate(brakeRate);
                                            bit64 = bit64 >>> 8;
                                            bit64 = bit64 >>> 2;
                                            int reserver = (int) (bit64 & 0x0F);
                                            bit64 = bit64 >>> 4;
                                            int carType = (int) (bit64 & 0x03);//车型类别
                                            mc.setCarType(carType);
                                            bit64 = bit64 >>> 2;
                                            int isCurrentOut = (int) (bit64 & 0x1);//任一相电流是否过流
                                            mc.setIsCurrentOut(isCurrentOut);
                                            bit64 = bit64 >>> 1;
                                            int isBusCurrentOut = (int) (bit64 & 0x1);//直流母线是否过流
                                            mc.setIsBusCurrentOut(isBusCurrentOut);
                                            bit64 = bit64 >>> 1;
                                            int isMotorRpmOut = (int) (bit64 & 0x1);//电机转速超过限值
                                            mc.setIsMotorRpmOut(isMotorRpmOut);
                                            bit64 = bit64 >>> 1;
                                            int isHolzerErr = (int) (bit64 & 0x1);//霍尔故障
                                            mc.setIsHolzerError(isHolzerErr);
                                            bit64 = bit64 >>> 1;
                                            int isAprErr = (int) (bit64 & 0x1);//加速踏板故障
                                            mc.setIsAprError(isAprErr);
                                            bit64 = bit64 >>> 1;
                                            int isGeerErr = (int) (bit64 & 0x1);//档位输入故障
                                            mc.setIsGeerError(isGeerErr);
                                            bit64 = bit64 >>> 1;
                                            // reserve
                                            bit64 = bit64 >>> 2;
                                            int motorLife = (int) (bit64 & 0xFF);//Life 值
                                            mc.setMotorLife(motorLife);
                                        } else if (canId == (int) 0x0CF13F05) {//MC_Error
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("MC_Error[0x0CF13F05]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int buscurrentSensorError = (int) (bit64 & 0x01);//母线电流传感器故障
                                            mc.setBusCurrentSensorError(buscurrentSensorError);
                                            bit64 = bit64 >>> 1;
                                            int phaseCurrentSensorError = (int) (bit64 & 0x01);//相线电流传感器故障
                                            mc.setPhaseCurrentSensorError(phaseCurrentSensorError);
                                            bit64 = bit64 >>> 1;
                                            int busVolSensorError = (int) (bit64 & 0x01);//母线电压传感器故障
                                            mc.setBusVolSensorError(buscurrentSensorError);
                                            bit64 = bit64 >>> 1;
                                            int controlTempSensorError = (int) (bit64 & 0x01);//控制器温度传感器故障
                                            mc.setControlTempSensorError(controlTempSensorError);
                                            bit64 = bit64 >>> 1;
                                            int mTempSensorError = (int) (bit64 & 0x01);//电机温度传感器故障
                                            mc.setmTempSensorError(mTempSensorError);
                                            bit64 = bit64 >>> 1;
                                            int rotaryTransformerError = (int) (bit64 & 0x01);//旋转变压器故障
                                            mc.setRotaryTransformerError(rotaryTransformerError);
                                            bit64 = bit64 >>> 1;
                                            int controlTempError = (int) (bit64 & 0x01);//控制器温度报警
                                            mc.setControlTempError(controlTempError);
                                            bit64 = bit64 >>> 1;
                                            int controlOuttempError = (int) (bit64 & 0x01);//控制器过温故障
                                            mc.setControlOuttempError(controlOuttempError);
                                            bit64 = bit64 >>> 1;
                                            int mTempAlarm = (int) (bit64 & 0x01);//电机温度报警
                                            mc.setmTempAlarm(mTempAlarm);
                                            bit64 = bit64 >>> 1;
                                            int mOuttempError = (int) (bit64 & 0x01);//电机过温故障
                                            mc.setmOuttempError(mOuttempError);
                                            bit64 = bit64 >>> 1;
                                            int busOutcurrent = (int) (bit64 & 0x01);//母线过流（短路）
                                            mc.setBusOutcurrent(busOutcurrent);
                                            bit64 = bit64 >>> 1;
                                            int busOutvolAlarm = (int) (bit64 & 0x01);//母线过压报警
                                            mc.setBusOutvolAlarm(busOutvolAlarm);
                                            bit64 = bit64 >>> 1;
                                            int busOutvolError = (int) (bit64 & 0x01);//母线过压故障
                                            mc.setBusOutvolError(busOutvolError);
                                            bit64 = bit64 >>> 1;
                                            int busUpdervolAlarm = (int) (bit64 & 0x01);//母线欠压报警
                                            mc.setBusUpdervolAlarm(busUpdervolAlarm);
                                            bit64 = bit64 >>> 1;
                                            int busUpdervolError = (int) (bit64 & 0x01);//母线欠压故障
                                            mc.setBusUpdervolError(busUpdervolError);
                                            bit64 = bit64 >>> 1;
                                            int controlUpdervolError = (int) (bit64 & 0x01);//控制电欠压故障
                                            mc.setControlUpdervolError(controlUpdervolError);
                                            bit64 = bit64 >>> 1;
                                            int controlOutvolError = (int) (bit64 & 0x01);//控制电过压故障
                                            mc.setControlOutvolError(controlOutvolError);
                                            bit64 = bit64 >>> 1;
                                            int phaseOutcurrent = (int) (bit64 & 0x01);//相线过流
                                            mc.setPhaseOutcurrent(phaseOutcurrent);
                                            bit64 = bit64 >>> 1;
                                            int mOutspeedAlarm = (int) (bit64 & 0x01);//电机超速报警
                                            mc.setmOutspeedAlarm(mOutspeedAlarm);
                                            bit64 = bit64 >>> 1;
                                            int mOutspeedError = (int) (bit64 & 0x01);//电机超速故障
                                            mc.setmOutspeedError(mOutspeedError);
                                            bit64 = bit64 >>> 1;
                                            int perchargeError = (int) (bit64 & 0x01);//预充电故障
                                            mc.setPerchargeError(perchargeError);
                                            bit64 = bit64 >>> 1;
                                            int pedalPersamplingError = (int) (bit64 & 0x01);//加速踏板预采样故障
                                            mc.setPedalPersamplingError(pedalPersamplingError);
                                            bit64 = bit64 >>> 1;
                                            int canCommunicatioonError = (int) (bit64 & 0x01);//CAN总线通讯故障
                                            mc.setCanCommunicationError(canCommunicatioonError);
                                            bit64 = bit64 >>> 1;
                                            int errorLevel = (int) (bit64 & 0x07);//故障等级
                                            mc.setErrorLevel(errorLevel);
                                            bit64 = bit64 >>> 3;
                                            int deratingLevel = (int) (bit64 & 0x03);//降功率等级
                                            mc.setDeratingLevel(deratingLevel);
                                            bit64 = bit64 >>> 2;
                                            int powerOutStatus = (int) (bit64 & 0x03);//动力输出状态
                                            mc.setPowerOutStatus(powerOutStatus);
                                            bit64 = bit64 >>> 2;
                                            bit64 = bit64 >>> 26;
                                            String supplierCode = Integer.toBinaryString((int) (bit64 & 0xFF));//供应商配置代码
                                            mc.setSupplierCode(supplierCode);

                                        } else if (canId == (int) 0x18FF50E5) {//obc CHARGER_BMS
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("CHARGER_BMS[0x18FF50E5]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float outVoltage = (float) ((bit64 & 0xFFFF) * 0.1f);//充电机输出电压
                                            outVoltage = BigDecimal.valueOf(outVoltage).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            obc.setOutVoltage(outVoltage);
                                            bit64 = bit64 >> 16;
                                            float outCurrent = (float) ((bit64 & 0xFFFF) * 0.1f);//充电机输出电流
                                            outCurrent = BigDecimal.valueOf(outCurrent).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            obc.setOutCurrent(outCurrent);
                                            bit64 = bit64 >> 16;
                                            int isHardErr = (int) (bit64 & 0x01);//硬件故障
                                            obc.setIsHardErr(isHardErr);
                                            bit64 = bit64 >> 1;
                                            int isTempHirgh = (int) (bit64 & 0x01);//充电机温度状态
                                            obc.setIsTempHigh(isTempHirgh);
                                            bit64 = bit64 >> 1;
                                            int isVoltageErr = (int) (bit64 & 0x01);//输入电压状态
                                            obc.setIsVoltageErr(isVoltageErr);
                                            bit64 = bit64 >> 1;
                                            int isRunning = (int) (bit64 & 0x01);//启动状态
                                            obc.setIsRunning(isRunning);
                                            bit64 = bit64 >> 1;
                                            int isConnected = (int) (bit64 & 0x01);//通信状态
                                            obc.setIsCommected(isConnected);
                                            bit64 = bit64 >> 1;
                                            int isReady = (int) (bit64 & 0x01);//充电准备就绪
                                            obc.setIsReady(isReady);
                                        } else if (canId == (int) 0x18FF51E5) {//obc ObcSt1
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            int inputVoltage = (int) (bit64 & 0x01FF);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("ObcSt1[0x18FF51E5]--->" + ByteBufUtil.hexDump(canBuffer));
                                            obc.setInVoltage((float) inputVoltage);
                                            bit64 = bit64 >> 9;
                                            float inputCurrent = (bit64 & 0x01FF) * 0.1f;
                                            inputCurrent = BigDecimal.valueOf(inputCurrent).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            obc.setInCurrent(inputCurrent);
                                            bit64 = bit64 >> 9;
                                            int pfcVoltage = (int) (bit64 & 0x01FF);
                                            obc.setPfcVoltage((float) pfcVoltage);
                                            bit64 = bit64 >> 9;
                                            // reserve
                                            bit64 = bit64 >> 5;
                                            float dv12Voltage = (bit64 & 0xFF) * 0.1f;
                                            dv12Voltage = BigDecimal.valueOf(dv12Voltage).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            obc.setV12Voltage(dv12Voltage);
                                            bit64 = bit64 >> 8;
                                            float dv12Current = (bit64 & 0x3F) * 0.1f;
                                            dv12Current = BigDecimal.valueOf(dv12Current).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            obc.setV12Current(dv12Current);
                                            bit64 = bit64 >> 6;
                                            // reserve
                                            bit64 = bit64 >> 2;
                                            float outPowerLevel = (bit64 & 0xFF) * 0.1f;
                                            outPowerLevel = BigDecimal.valueOf(outPowerLevel).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();

                                            bit64 = bit64 >> 8;
                                            int outCurrentLevel = (int) (bit64 & 0x3F);
                                        } else if (canId == (int) 0x18FF52E5) {//OBC_St2
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("OBC_St2[0x18FF52E5]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int temp1 = (int) ((bit64 & 0xFF) - 50);//温度1
                                            obc.setTemprature1(temp1);
                                            bit64 = bit64 >>> 8;
                                            int temp2 = (int) ((bit64 & 0xFF) - 50);//温度2
                                            obc.setTemprature2(temp2);
                                            bit64 = bit64 >>> 8;
                                            int temp3 = (int) ((bit64 & 0xFF) - 50);//温度3
                                            obc.setTemprature3(temp3);
                                            bit64 = bit64 >>> 8;
                                            int fanStatus = (int) (bit64 & 0x03);//风扇状态
                                            obc.setFanStatus(fanStatus);
                                            bit64 = bit64 >>> 2;
                                            int chargeStatus = (int) (bit64 & 0x03);//充电状态
                                            obc.setChargerStatus(chargeStatus);
                                            bit64 = bit64 >>> 2;
                                            int chargeTempStatus = (int) (bit64 & 0x03);//充电机温度异常监控
                                            obc.setTempratureError(chargeTempStatus);
                                            bit64 = bit64 >>> 2;
                                            bit64 = bit64 >>> 2;
                                            int inputVoltageLow1 = (int) (bit64 & 0x01);//输入欠压1
                                            obc.setInUpdervoltage1(inputVoltageLow1);
                                            bit64 = bit64 >>> 1;
                                            int inputVoltageLow2 = (int) (bit64 & 0x01);//输入欠压2
                                            obc.setInUpdervoltage2(inputVoltageLow2);
                                            bit64 = bit64 >>> 1;
                                            int inputVoltageHigh = (int) (bit64 & 0x01);//输入过压
                                            obc.setInOutvoltage(inputVoltageHigh);
                                            bit64 = bit64 >>> 1;
                                            int outVoltageLow = (int) (bit64 & 0x01);//高压输出欠压
                                            obc.setHighvolOutOutdervol(outVoltageLow);
                                            bit64 = bit64 >>> 1;
                                            int outVoltageHigh = (int) (bit64 & 0x01);//高压输出过压
                                            obc.setHighvolOutOutdervol(outVoltageHigh);
                                            bit64 = bit64 >>> 1;
                                            int outCurrentBig = (int) (bit64 & 0x01);//输出过流
                                            obc.setOutOutcurrent(outCurrentBig);
                                            bit64 = bit64 >>> 2;
                                            int pfcErr = (int) (bit64 & 0x01);//PFC电压异常
                                            obc.setPfcVolError(pfcErr);
                                            bit64 = bit64 >>> 1;
                                            int charger12DcHighErr = (int) (bit64 & 0x01);//充电机12V过压异常
                                            obc.setV12OutvolError(charger12DcHighErr);
                                            bit64 = bit64 >>> 1;
                                            int charger12DcLowErr = (int) (bit64 & 0x01);//充电机12V欠压异常
                                            obc.setV12UpdervolError(charger12DcLowErr);
                                        } else {
                                            System.out.println("Unsupport packet,canId=" + canId + ",buf=" + ByteBufUtil.hexDump(canBuffer));
                                        }
                                    }
                                    /*==========add===========*/
                                    dataPackTargetList.add(new DataPackTarget(hvac));//hvac数据
                                    dataPackTargetList.add(new DataPackTarget(bcm));
                                    //bcm
                                    dataPackTargetList.add(new DataPackTarget(vms));
                                    //vms
                                    dataPackTargetList.add(new DataPackTarget(peps));
                                    //peps
                                    dataPackTargetList.add(new DataPackTarget(eps));
                                    //eps
                                    dataPackTargetList.add(new DataPackTarget(adas));
                                    //adas
                                    bms.setVoltage(voltageArray);// 单体电池电压数组
                                    bms.setTemprature(tempratureArray);// 探头温度数组
                                    dataPackTargetList.add(new DataPackTarget(bms));
                                    //bms
                                    dataPackTargetList.add(new DataPackTarget(obc));
                                    dataPackTargetList.add(new DataPackTarget(mc));

                                    index = index + length;//索引增加
                                } else {
                                    break;
                                }
                            }
                        }
                        break;
                    case 0x03://心跳数据
                        System.out.println("## 0x03 - 心跳数据");

                        break;
                    case 0x04://补发信息上报
                        System.out.println("补发信息上报");
                        //获取数据包体
                        byte[] dataBufferDelay = new byte[msgLength - 6];
                        //读取消息头部24个byte
                        buffer.readBytes(24);

                        //数据采集时间
                        byte[] collectTimeBufDelay = new byte[6];
                        buffer.readBytes(collectTimeBufDelay);
                        //数据采集时间
                        Date detectionTimeDelay = new Date(D2sDataPackUtil.buf2Date(collectTimeBufDelay, 0));
                        // 6.检验时间
                        dataPackObject.setDetectionTime(detectionTimeDelay);
                        //读取消息体数据到byte数组
                        buffer.readBytes(dataBufferDelay);
                        System.out.println("车辆运行信息上报补发:" + ByteBufUtil.hexDump(dataBufferDelay));

                        if (dataBufferDelay != null && dataBufferDelay.length > 0) {
                            int index = 0;
                            while (index < (msgLength - 6)) {
                                if (dataBufferDelay[index] == (byte) 0x01) { // 动力蓄电池电气数据
                                    DataPackBattery dataPackBattery = new DataPackBattery(dataPackObject);

                                    //设置vin码
                                    //  dataPackBattery.setVin(iccid);
                                    index += 1;
                                    int length = 11 + (dataBufferDelay[index + 10] & 0xFF) * 2;
                                    byte[] eleBuffer = new byte[length];
                                    System.arraycopy(dataBufferDelay, index, eleBuffer, 0, length);
                                    //打印调试信息
                                    D2sDataPackUtil.debug("动力蓄电池电气数据--->" + ByteBufUtil.hexDump(eleBuffer));
                                    //动力蓄电池字子系统个数
                                    Integer batterySysNumber = eleBuffer[0] & 0xFF;
                                    dataPackBattery.setBatterySysNumber(batterySysNumber);
                                    //电池子系统号
                                    Integer batterySysIndex = eleBuffer[1] & 0xFF;
                                    dataPackBattery.setBatterySysIndex(batterySysIndex);
                                    //动力蓄电池电压
                                    Float totalVoltage = (float) ((eleBuffer[2] & 0xFF) << 8 | (eleBuffer[3] & 0xFF)) / 10;
                                    totalVoltage = new BigDecimal(totalVoltage).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackBattery.setTotalVoltage(totalVoltage);
                                    //动力蓄电池电流
                                    Float totalCurrent = (float) ((eleBuffer[4] & 0xFF) << 8 | (eleBuffer[5] & 0xFF)) / 10 - 1000;
                                    totalCurrent = new BigDecimal(totalCurrent).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackBattery.setTotalCurrent(totalCurrent);
                                    //单体蓄电池总数
                                    Integer batteryNumber = (eleBuffer[6] & 0xFF) << 8 | (eleBuffer[7] & 0xFF);
                                    //本帧起始电池序号
                                    Integer batteryStartIndex = (eleBuffer[8] & 0xFF) << 8 | (eleBuffer[9] & 0xFF);
                                    //本帧单体电池总数
                                    Integer batteryPacketNumber = eleBuffer[10] & 0xFF;
                                    //单体电压数组
                                    List<Float> batteryVoltageList = new ArrayList<>();
                                    for (int i = 0; i < batteryPacketNumber; i++) {
                                        batteryVoltageList.add(new BigDecimal(((float) ((eleBuffer[11 + i * 2] & 0xFF) << 8 | (eleBuffer[12 + i * 2] & 0xFF)) / 1000)).setScale(3, BigDecimal.ROUND_HALF_UP).floatValue());
                                    }
                                    dataPackBattery.setBatteryVoltages(batteryVoltageList);
                                    //-add
                                    dataPackTargetList.add(new DataPackTarget(dataPackBattery));
                                    //索引增加
                                    index = index + length;
                                } else if (dataBufferDelay[index] == (byte) 0x02) { // 动力蓄电池包温度数据
                                    DataPackTemperature dataPackTemperature = new DataPackTemperature(dataPackObject);
                                    //设置vin码
                                    //   dataPackTemperature.setVid(iccid);
                                    index += 1;
                                    int length = 4 + ((dataBufferDelay[index + 2] & 0xFF << 8) | (dataBufferDelay[index + 3] & 0xFF));
                                    byte[] eleBuffer = new byte[length];
                                    System.arraycopy(dataBufferDelay, index, eleBuffer, 0, length);
                                    //打印调试信息
                                    D2sDataPackUtil.debug("动力蓄电池电气数据--->" + ByteBufUtil.hexDump(eleBuffer));
                                    //动力蓄电池总成个数
                                    Integer batterySysNumber = eleBuffer[0] & 0xFF;
                                    dataPackTemperature.setBatterySysNumber(batterySysNumber);
                                    //电池子系统号
                                    Integer sysIndex = eleBuffer[1] & 0xFF;
                                    dataPackTemperature.setSysIndex(sysIndex);
                                    //电池温度探针个数
                                    Integer number = (eleBuffer[2] & 0xFF) << 8 | (eleBuffer[3] & 0xFF);
                                    dataPackTemperature.setNumber(number);
                                    //电池总各温度探针检测到的温度值
                                    List<Integer> temperatureList = new ArrayList<>();
                                    for (int i = 0; i < number; i++) {
                                        temperatureList.add((eleBuffer[4 + i] & 0xFF) - 40);
                                    }
                                    dataPackTemperature.setTemperatureList(temperatureList);
                                    //-add
                                    dataPackTargetList.add(new DataPackTarget(dataPackTemperature));
                                    index = index + length;
                                } else if (dataBufferDelay[index] == (byte) 0x03) { // 整车数据
                                    DataPackOverview dataPackOverview = new DataPackOverview(dataPackObject);
                                    //     dataPackOverview.setVin(iccid);
                                    index += 1;
                                    int length = 20;
                                    byte[] eleBuffer = new byte[length];
                                    System.arraycopy(dataBufferDelay, index, eleBuffer, 0, length);
                                    //打印调试信息
                                    D2sDataPackUtil.debug("整车数据--->" + ByteBufUtil.hexDump(eleBuffer));
                                    //车辆状态
                                    Integer vehicleStatus = eleBuffer[0] & 0xFF;
                                    dataPackOverview.setCarStatus(vehicleStatus);
                                    //充电状态
                                    Integer chargeStatus = eleBuffer[1] & 0xFF;
                                    dataPackOverview.setChargeStatus(chargeStatus);
                                    //运行模式
                                    Integer runStatus = eleBuffer[2] & 0xFF;
                                    dataPackOverview.setRunStatus(runStatus);
                                    //车速
                                    Float vehicleSpeed = (float) ((eleBuffer[3] & 0xFF) << 8 | (eleBuffer[4] & 0xFF)) / 10;
                                    vehicleSpeed = new BigDecimal(vehicleSpeed).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackOverview.setVehicleSpeed(vehicleSpeed);
                                    //累计里程
                                    Double mileAge = (double) ((eleBuffer[5] & 0xFF) << 24 | (eleBuffer[6] & 0xFF) << 16 | (eleBuffer[7] & 0xFF) << 8 | (eleBuffer[8] & 0xFF));
                                    mileAge = new BigDecimal(mileAge).setScale(1, BigDecimal.ROUND_HALF_UP).doubleValue();
                                    dataPackOverview.setMileage(mileAge);
                                    //总电压
                                    Float totalVoltage = (float) ((eleBuffer[9] & 0xFF) << 8 | (eleBuffer[10] & 0xFF)) / 10;
                                    totalVoltage = new BigDecimal(totalVoltage).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackOverview.setVoltage(totalVoltage);
                                    //总电流
                                    Float totalCurrent = (float) ((eleBuffer[11] & 0xFF) << 8 | (eleBuffer[12] & 0xFF)) / 10 - 1000;
                                    totalCurrent = new BigDecimal(totalCurrent).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackOverview.setTotalCurrent(totalCurrent);
                                    //SOC
                                    Integer soc = eleBuffer[13] & 0xFF;
                                    dataPackOverview.setSoc(soc);
                                    //DC-DC 状态
                                    Integer dcdcStatus = eleBuffer[14] & 0xFF;
                                    dataPackOverview.setDcdcStatus(dcdcStatus);
                                    //档位
                                    Integer clutchStatus = eleBuffer[15] & 0x0F;
                                    dataPackOverview.setClutchStatus(clutchStatus);
                                    //制动状态
                                    Integer driveBrakeStatus = eleBuffer[15] >>> 4 & 0x03;
                                    dataPackOverview.setDriveBrakeStatus(driveBrakeStatus);
                                    //绝缘电阻
                                    Integer issueValue = (eleBuffer[16] & 0xFF) << 8 | eleBuffer[17] & 0xFF;
                                    dataPackOverview.setIssueValue(issueValue);
                                    //-add
                                    dataPackTargetList.add(new DataPackTarget(dataPackOverview));
                                    index = index + length;

                                } else if (dataBufferDelay[index] == (byte) 0x04) { // 汽车电机部分数据
                                    index += 1;
                                    int length = 13;
                                    DataPackMotor dataPackMotor = new DataPackMotor(dataPackObject);
                                    //        dataPackMotor.setVin(iccid);
                                    byte[] eleBuffer = new byte[length];
                                    System.arraycopy(dataBufferDelay, index, eleBuffer, 0, length);
                                    //打印调试信息
                                    D2sDataPackUtil.debug("汽车电机部分数据--->" + ByteBufUtil.hexDump(eleBuffer));
                                    //电机个数
                                    Integer motorNumber = eleBuffer[0] & 0xFF;
                                    dataPackMotor.setMotorTotal(motorNumber);
                                    //电机序号
                                    Integer motorIndex = eleBuffer[1] & 0xFF;
                                    dataPackMotor.setMotorSeq(motorIndex);
                                    //驱动电机状态
                                    Integer motorStatus = eleBuffer[2] & 0xFF;
                                    dataPackMotor.setMotorStatus(motorStatus);
                                    //驱动电机控制器温度
                                    Integer motorControlerTemperature = (eleBuffer[3] & 0xFF) - 40;
                                    dataPackMotor.setControllerTemperature(motorControlerTemperature);
                                    //驱动电机转速
                                    Integer motorRpm = ((eleBuffer[4] & 0xFF) << 8 | eleBuffer[5] & 0xFF) - 20000;
                                    dataPackMotor.setSpeed(motorRpm);
                                    //驱动电机转矩
                                    Float motorNm = (float) (((eleBuffer[6] & 0xFF) << 8 | (eleBuffer[7] & 0xFF)) - 20000) / 10;
                                    motorNm = new BigDecimal(motorNm).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackMotor.setTorque(motorNm);
                                    //驱动电机温度
                                    Integer motorTemperature = (eleBuffer[8] & 0xFF) - 40;
                                    dataPackMotor.setMotorTemperature(motorTemperature);
                                    //电机控制器输入电压
                                    Float motorInputVoltage = (float) ((eleBuffer[9] & 0xFF) << 8 | (eleBuffer[10] & 0xFF)) / 10;
                                    motorInputVoltage = new BigDecimal(motorInputVoltage).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackMotor.setControllerInputVoltage(motorInputVoltage);
                                    //电机控制器直流母线电流
                                    Float motorBusCurrent = (float) ((eleBuffer[11] & 0xFF) << 8 | (eleBuffer[12] & 0xFF)) / 10 - 1000;
                                    motorBusCurrent = new BigDecimal(motorBusCurrent).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackMotor.setControllerDirectCurrent(motorBusCurrent);
                                    //-add
                                    dataPackTargetList.add(new DataPackTarget(dataPackMotor));
                                    index = index + length;

                                } else if (dataBufferDelay[index] == (byte) 0x07) { // 车辆位置数据
                                    index += 1;
                                    int length = 21;
                                    dataPackPosition = new DataPackPosition(dataPackObject);
                                    //      dataPackPosition.setVin(iccid);
                                    dataPackPosition.setPositionTime(Calendar.getInstance().getTime());
                                    byte[] eleBuffer = new byte[length];
                                    System.arraycopy(dataBufferDelay, index, eleBuffer, 0, length);
                                    //打印调试信息
                                    D2sDataPackUtil.debug("车辆位置数据--->" + ByteBufUtil.hexDump(eleBuffer));
                                    //定位状态
                                    Integer isValidate = eleBuffer[0] & 0x01;
                                    dataPackPosition.setIsValidate(isValidate);
                                    //0:北纬； 1:南纬
                                    Integer latType = eleBuffer[0] & 0x02;
                                    //0:东经； 1:西经
                                    Integer lngType = eleBuffer[0] & 0x04;
                                    //经度
                                    Double longitude = (double) ((eleBuffer[1] & 0xFF) << 24 | (eleBuffer[2] & 0xFF) << 16 | (eleBuffer[3] & 0xFF) << 8 | (eleBuffer[4] & 0xFF)) * 0.000001f;
                                    longitude = new BigDecimal(longitude).setScale(6, BigDecimal.ROUND_HALF_UP).doubleValue();
                                    dataPackPosition.setLongitude(longitude);
                                    //纬度
                                    Double latitude = (double) ((eleBuffer[5] & 0xFF) << 24 | (eleBuffer[6] & 0xFF) << 16 | (eleBuffer[7] & 0xFF) << 8 | (eleBuffer[8] & 0xFF)) * 0.000001f;
                                    latitude = new BigDecimal(latitude).setScale(6, BigDecimal.ROUND_HALF_UP).doubleValue();
                                    dataPackPosition.setLatitude(latitude);
                                    //速度
                                    Float speed = (float) ((eleBuffer[9] & 0xFF) << 8 | (eleBuffer[10] & 0xFF)) / 10;
                                    speed = new BigDecimal(speed).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                    dataPackPosition.setSpeed(speed);
                                    //海拔
                                    Double altitude = (double) ((eleBuffer[11] & 0xFF) << 24 | (eleBuffer[12] & 0xFF) << 16 | (eleBuffer[13] & 0xFF) << 8 | (eleBuffer[14] & 0xFF)) / 10;
                                    altitude = new BigDecimal(altitude).setScale(1, BigDecimal.ROUND_HALF_UP).doubleValue();
                                    dataPackPosition.setAltitude(altitude);
                                    //方向
                                    Float direction = (float) ((eleBuffer[15] & 0xFF) << 8 | (eleBuffer[16] & 0xFF));
                                    dataPackPosition.setDirection(direction);
                                    dataPackTargetList.add(new DataPackTarget(dataPackPosition));
                                    index = index + length;

                                } else if (dataBufferDelay[index] == (byte) 0x08) { // 极值数据
                                    index += 1;
                                    int length = 14;
                                    DataPackPeak dataPackPeak = new DataPackPeak(dataPackObject);
                                    List<DataPackPeak.Peak> peakList = new ArrayList<>();
                                    //     dataPackPeak.setVin(iccid);
                                    byte[] eleBuffer = new byte[length];
                                    System.arraycopy(dataBufferDelay, index, eleBuffer, 0, length);
                                    //打印调试信息
                                    D2sDataPackUtil.debug("极值数据--->" + ByteBufUtil.hexDump(eleBuffer));

                                    //最高电压电池子系统号
                                    Integer batterySystemMaxNo = eleBuffer[0] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最高电压电池子系统号",
                                            batterySystemMaxNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));

                                    //最高电压电池单体代号
                                    Integer batteryVoltageMaxNo = eleBuffer[1] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最高电压电池单体代号",
                                            batteryVoltageMaxNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));

                                    //电池单体电压最高值
                                    Float batteryVoltageMaxValue = (float) ((eleBuffer[2] & 0xFF) << 8 | (eleBuffer[3] & 0xFF)) / 1000;
                                    batteryVoltageMaxValue = new BigDecimal(batteryVoltageMaxValue).setScale(3, BigDecimal.ROUND_HALF_UP).floatValue();
                                    peakList.add(new DataPackPeak.Peak(null, "电池单体电压最高值",
                                            batteryVoltageMaxValue.toString(), "V", "有效值范围： 0～15000（表示 0V～15V）"));

                                    //最低电压电池子系统号
                                    Integer batterySystemMinNo = eleBuffer[4] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最低电压电池子系统号",
                                            batterySystemMinNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));


                                    //最低电压电池单体代号
                                    Integer batteryVoltageMinNo = eleBuffer[5] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最低电压电池单体代号",
                                            batteryVoltageMinNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));


                                    //电池单体电压最低值
                                    Float batteryVoltageMinValue = (float) ((eleBuffer[6] & 0xFF) << 8 | (eleBuffer[7] & 0xFF)) / 1000;
                                    batteryVoltageMinValue = new BigDecimal(batteryVoltageMinValue).setScale(3, BigDecimal.ROUND_HALF_UP).floatValue();
                                    peakList.add(new DataPackPeak.Peak(null, "最高电压电池单体代号",
                                            batteryVoltageMinValue.toString(), "V", "有效值范围： 0～15000（表示 0V～15V）"));


                                    //最高温度子系统号
                                    Integer temperatureHighestSystemNo = eleBuffer[8] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最高温度子系统号",
                                            temperatureHighestSystemNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));


                                    //最高温度探针单体代号
                                    Integer temperatureHighestNo = eleBuffer[9] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最高温度探针单体代号",
                                            temperatureHighestNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));

                                    //蓄电池中最高温度值
                                    Integer temperatureHighestValue = (eleBuffer[10] & 0xFF) - 40;
                                    peakList.add(new DataPackPeak.Peak(null, "蓄电池中最高温度值",
                                            temperatureHighestValue.toString(), "℃", "有效值范围： 0～250（数值偏移量 40℃，表示-40℃～+210℃）"));

                                    //最低温度子系统号
                                    Integer temperatureLowestSystemNo = eleBuffer[11] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最低温度子系统号",
                                            temperatureLowestSystemNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));

                                    //最低温度探针子系统代号
                                    Integer temperatureLowestNo = eleBuffer[12] & 0xFF;
                                    peakList.add(new DataPackPeak.Peak(null, "最低温度探针子系统代号",
                                            temperatureLowestNo.toString(), null, "有效值范围：1～250，“0xFE”表示异常，“0xFF”表示无效。"));

                                    //蓄电池中最低温度值
                                    Integer temperatureLowestValue = (eleBuffer[13] & 0xFF) - 40;
                                    peakList.add(new DataPackPeak.Peak(null, "蓄电池中最低温度值",
                                            temperatureLowestValue.toString(), "℃", "有效值范围： 0～250（数值偏移量 40℃，表示-40℃～+210℃）"));

                                    dataPackPeak.setPeakList(peakList);
                                    //-add
                                    dataPackTargetList.add(new DataPackTarget(dataPackPeak));

                                    index = index + length;
                                } else if (dataBufferDelay[index] == (byte) 0x09) { // 透传数据
                                    //can数据
                                    DataPackCanHvac hvac = new DataPackCanHvac(dataPackObject);//hvac数据
                                    hvac.setDetectionTime(detectionTimeDelay);
                                    hvac.setDeviceId(iccid);
                                    DataPackCanBcm bcm = new DataPackCanBcm(dataPackObject);//bcm
                                    bcm.setDetectionTime(detectionTimeDelay);
                                    bcm.setDeviceId(iccid);
                                    DataPackCanVms vms = new DataPackCanVms(dataPackObject);//vms
                                    vms.setDetectionTime(detectionTimeDelay);
                                    vms.setDeviceId(iccid);
                                    DataPackCanPeps peps = new DataPackCanPeps(dataPackObject);//peps
                                    peps.setDetectionTime(detectionTimeDelay);
                                    peps.setDeviceId(iccid);
                                    DataPackCanEps eps = new DataPackCanEps(dataPackObject);//eps
                                    eps.setDetectionTime(detectionTimeDelay);
                                    eps.setDeviceId(iccid);
                                    DataPackCanAdas adas = new DataPackCanAdas(dataPackObject);//adas
                                    adas.setDetectionTime(detectionTimeDelay);
                                    adas.setDeviceId(iccid);
                                    DataPackCanBms bms = new DataPackCanBms(dataPackObject);//bms
                                    bms.setDetectionTime(detectionTimeDelay);
                                    bms.setDeviceId(iccid);
                                    Float[] voltageArray = new Float[42]; // 单体电池电压数组
                                    Integer[] tempratureArray = new Integer[12]; // 探头温度数组
                                    DataPackCanObc obc = new DataPackCanObc(dataPackObject);//obc
                                    obc.setDetectionTime(detectionTimeDelay);
                                    obc.setDeviceId(iccid);
                                    DataPackCanMc mc = new DataPackCanMc(dataPackObject);//mc
                                    mc.setDetectionTime(detectionTimeDelay);
                                    mc.setDeviceId(iccid);

                                    index += 1;
                                    int canPacketNumber = dataBufferDelay[index] & 0xFF;
                                    int length = canPacketNumber * 12;
                                    index += 1;
                                    byte[] canAllBuffer = new byte[length];
                                    System.arraycopy(dataBufferDelay, index, canAllBuffer, 0, length);

                                    //打印调试信息
                                    D2sDataPackUtil.debug("透传数据--->" + ByteBufUtil.hexDump(canAllBuffer));

                                    int offset = 0;
                                    for (int i = 0; i < canPacketNumber; i++) {
                                        //can id
                                        int canId = D2sDataPackUtil.getInt4Bigendian(canAllBuffer, offset + i * 12, offset + i * 12 + 4);
                                        byte[] canBuffer = D2sDataPackUtil.getRange(canAllBuffer, offset + i * 12 + 4, offset + i * 12 + 12);
                                        DataPackCanVersion dataPackCanVersion = null;
                                        if (canId == (int) 0x18FF64DA) { //icu版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("icu");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("icu版本[0x18FF64DA]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF6401) { //vms版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("vms");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("vms版本[0x18FF6401]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64F4) {//bms版本

                                        } else if (canId == (int) 0x18FF64EF) {//mc版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("mc");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("mc版本[0x18FF64EF]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64DD) {//peps版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("peps");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("peps版本[0x18FF64DD]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64E5) {//obc版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("obc");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("obc版本[0x18FF64E5]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64DE) {//hvac版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("hvac");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("hvac版本[0x18FF64DE]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64E7) {//gprs版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("gprs");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("gprs版本[0x18FF64E7]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64DC) {//bcm版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("bcm");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("bcm版本[0x18FF64DC]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64DF) {//adas版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("adas");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[4];
                                            System.arraycopy(canBuffer, 0, bf, 0, 4);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("adas版本[0x18FF64DF]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 4));
                                        } else if (canId == (int) 0x18FF64DB) {//gps版本
                                            dataPackCanVersion = new DataPackCanVersion(dataPackObject);
                                            dataPackCanVersion.setCanModelName("gps");
                                            dataPackCanVersion.setCanId(canId);
                                            byte[] bf = new byte[6];
                                            System.arraycopy(canBuffer, 0, bf, 0, 6);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("gps版本[0x18FF64DB]--->" + ByteBufUtil.hexDump(bf));
                                            dataPackCanVersion.setVersion(D2sDataPackUtil.getAsciiString(bf, 0, 6));
                                        } else if (canId == (int) 0x08FF00DD) {//peps PEPS_SEND1_MSG
                                            //打印调试信息
                                            D2sDataPackUtil.debug("PEPS_SEND1_MSG[0x08FF00DD]--->" + ByteBufUtil.hexDump(canBuffer));
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            int rkeLockCmd = (int) (bit64 & 0x0F);//遥控器状态
                                            peps.setRkelockCmd(rkeLockCmd);
                                            bit64 = bit64 >> 4;
                                            int pkeLockCmd = (int) (bit64 & 0x0F);//无钥匙进入状态
                                            peps.setPkelockCmd(pkeLockCmd);
                                            bit64 = bit64 >> 4;
                                            int pepsBcmAlarm = (int) (bit64 & 0x0F);//PepsBcmAlarm
                                            peps.setPepsbcmAlarm(pepsBcmAlarm);
                                            bit64 = bit64 >> 4;
                                            int pepsIcuAlarm = (int) (bit64 & 0x0F);//仪表报警提示
                                            peps.setPepsicuAlarm(pepsIcuAlarm);
                                            bit64 = bit64 >> 4;
                                            int pepsEscLpowerEnable = (int) (bit64 & 0x03);//ESCL电源状态
                                            peps.setPepsEsclpowerEnable(pepsEscLpowerEnable);
                                            bit64 = bit64 >> 2;
                                            int sysPowMode = (int) (bit64 & 0x03);//整车电源档位
                                            peps.setSyspowMode(sysPowMode);
                                            bit64 = bit64 >> 2;
                                            int fobIndex = (int) (bit64 & 0x07);//
                                            peps.setFobIndex(fobIndex);
                                            bit64 = bit64 >> 3;
                                            int crankRequest = (int) (bit64 & 0x01);//启动请求
                                            peps.setCrankRequest(crankRequest);
                                            bit64 = bit64 >> 1;
                                            int esclStatus = (int) (bit64 & 0x01);//ESCL状态
                                            peps.setEsclStatus(esclStatus);
                                        } else if (canId == (int) 0x08FF01DD) {//peps
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("peps[0x08FF01DD]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int fobPosition = (byte) (bit64 & 0x07);//钥匙位置
                                            peps.setFobPosition(fobPosition);
                                            bit64 = bit64 >> 3;
                                            int pepsAuthResult = (byte) (bit64 & 0x01);//认证状态
                                            peps.setAuthenticationStatus(pepsAuthResult);
                                            bit64 = bit64 >> 1;
                                            int backupKeyStatus = (byte) (bit64 & 0x01);//备用钥匙状态
                                            peps.setSpareKeyStatus(backupKeyStatus);
                                            bit64 = bit64 >> 1;
                                            int ssbSw1 = (byte) (bit64 & 0x01);//启动按键状态
                                            peps.setSsbSw1(ssbSw1);
                                            bit64 = bit64 >> 1;
                                            int ssbSw2 = (byte) (bit64 & 0x01);//启动按键状态
                                            peps.setSsbSw2(ssbSw2);
                                            bit64 = bit64 >> 1;
                                            int driverdDoorSw = (byte) (bit64 & 0x01);//驾驶门状态
                                            peps.setDriverdDoorStatus(driverdDoorSw);
                                            bit64 = bit64 >> 1;
                                            int passDoorSw = (byte) (bit64 & 0x01);//副驾门状态
                                            peps.setPassDoorSwStatus(passDoorSw);
                                            bit64 = bit64 >> 1;
                                            int trunkSw = (byte) (bit64 & 0x01);//尾门状态
                                            peps.setTrunksw(trunkSw);
                                            bit64 = bit64 >> 1;
                                            int brakeSW = (byte) (bit64 & 0x01);//制动踏板状态
                                            peps.setBrakeSw(brakeSW);
                                            bit64 = bit64 >> 1;
                                            int accFb = (byte) (bit64 & 0x01);//ACC电源状态
                                            peps.setAccFb(accFb);
                                            bit64 = bit64 >> 1;
                                            int onFb = (byte) (bit64 & 0x01);//ON电源状态
                                            peps.setOnFb(onFb);
                                            bit64 = bit64 >> 1;
                                            int accCtrl = (byte) (bit64 & 0x01);//ACC控制信号
                                            peps.setAccCtrl(accCtrl);
                                            bit64 = bit64 >> 1;
                                            int onCtrl = (byte) (bit64 & 0x01);//ON控制信号
                                            peps.setOnCtrl(onCtrl);
                                            bit64 = bit64 >> 1;
                                            int esclUnlockFb = (byte) (bit64 & 0x01);//escl解锁
                                            peps.setEsclUnlockFb(esclUnlockFb);
                                            bit64 = bit64 >> 1;
                                            int esclLockEn = (byte) (bit64 & 0x01);//escl上锁
                                            peps.setEsclLockEn(esclLockEn);
                                            bit64 = bit64 >> 1;//
                                            bit64 = bit64 >> 7;//
                                            int vSpeed = (int) (bit64 & 0xFF);//车速
                                            peps.setvSpeed(vSpeed);
                                            bit64 = bit64 >> 8;
                                            int eSpeed = (int) (bit64 & 0xFF);//电机转速
                                            peps.seteSpeed(eSpeed);
                                        } else if (canId == (int) 0x1CFF00DE) {//HVAC_General_MSG
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("HVAC_General_MSG[0x1CFF00DE]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int runstatus = (int) (bit64 & 0x03);//空调启动状态
                                            hvac.setRunStatus(runstatus);
                                            bit64 = bit64 >>> 2;
                                            int level = (int) (bit64 & 0x0F);//空调风机档位
                                            hvac.setHvacLevel(level);
                                            bit64 = bit64 >>> 4;
                                            bit64 = bit64 >>> 2;
                                            int power = (int) (bit64 & 0xFFFF);//空调功率
                                            hvac.setPower(power);
                                            bit64 = bit64 >>> 16;
                                            int exTemp = (int) (bit64 & 0xFF - 40);//车外温度
                                            hvac.setExTemp(exTemp);
                                            bit64 = bit64 >>> 8;
                                            int innerTemp = (int) (bit64 & 0xFF - 40);//车内温度
                                            hvac.setInnerTemp(innerTemp);
                                            bit64 = bit64 >>> 8;
                                            int crondDirection = (int) (bit64 & 0x07);//空调风向状态
                                            hvac.setCrondDirection(crondDirection);
                                            bit64 = bit64 >>> 3;
                                            int cirleModel = (int) (bit64 & 0x01);//空调循环模式状态
                                            hvac.setCirleModel(cirleModel);
                                        } else if (canId == (int) 0x1CFF01DE) {//HVAC_FaultList_MSG
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("HVAC_FaultList_MSG[0x1CFF01DE]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int errModel = 0;//模式电机故障
                                            if ((bit64 & 0x01) == 0x00) {
                                                errModel = 0x00;
                                            } else {
                                                errModel = 0x01;
                                            }
                                            hvac.setErrModel(errModel);
                                            bit64 = bit64 >> 1;
                                            int errTemp = 0;//温度电机故障
                                            if ((bit64 & 0x01) == 0x00) {
                                                errTemp = 0x00;
                                            } else {
                                                errTemp = 0x01;
                                            }
                                            hvac.setErrTemp(errTemp);
                                            bit64 = bit64 >> 1;
                                            int errEvalsensor = 0;//蒸发器传感器故障
                                            if ((bit64 & 0x01) == 0x00) {
                                                errEvalsensor = 0x00;
                                            } else {
                                                errEvalsensor = 0x01;
                                            }
                                            hvac.setErrEvalsensor(errEvalsensor);
                                            bit64 = bit64 >> 1;
                                            int errTempSensor = 0;//回风温度传感器故障
                                            if ((bit64 & 0x01) == 0x00) {
                                                errTempSensor = 0x00;
                                            } else {
                                                errTempSensor = 0x01;
                                            }
                                            hvac.setErrTempSensor(errTempSensor);
                                        } else if (canId == (int) 0x1CFF00DA) {//icu
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("icu[0x1CFF00DA]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float mileAge = (bit64 & 0xFFFFFF) * 0.1f;
                                            BigDecimal bigDecimal = new BigDecimal(mileAge); //总里程
                                            mileAge = bigDecimal.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            bit64 = bit64 >>> 32;
                                            int brakeSysAlarm = (int) (bit64 & 0x01); //制动系统报警
                                            bit64 = bit64 >>> 1;
                                            int keepInfo = (int) (bit64 & 0x03);
                                            bit64 = bit64 >>> 2;
                                            float leaveMileAge = (bit64 & 0xFFFF) * 0.1f;
                                            BigDecimal bigDecimal1 = new BigDecimal(mileAge); //里程
                                            leaveMileAge = bigDecimal1.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                        } else if (canId == (int) 0x0CFF00DC) {//bcm BCM_General
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BCM_General[0x0CFF00DC]--->" + ByteBufUtil.hexDump(canBuffer));
                                            Integer runStatus = (int) (bit64 & 0x0F);//BCM运行状态（阶段）
                                            bcm.setRunStatus(runStatus);

                                            bit64 = bit64 >> 4;
                                            int errLevel = (int) (bit64 & 0x03);//BCM故障等级
                                            bcm.setErrLevel(errLevel);

                                            bit64 = bit64 >> 2;
                                            int brakeStatus = (int) (bit64 & 0x01);//脚刹状态
                                            bcm.setBrakeStatus(brakeStatus);

                                            bit64 = bit64 >> 1;
                                            int handbrakeStatus = (int) (bit64 & 0x01);//手刹是否拉起
                                            bcm.setHandbrakeStatus(handbrakeStatus);

                                            bit64 = bit64 >> 1;
                                            int iscrash = (int) (bit64 & 0x01);//碰撞是否发生bit64 = bit64 >> 1;
                                            bcm.setIscrash(iscrash);

                                            bit64 = bit64 >> 1;
                                            int dc12level = (int) (bit64 & 0x0F);//12V电源档位
                                            bcm.setDc12Level(dc12level);

                                            bit64 = bit64 >> 4;
                                            bit64 = bit64 >> 1;
                                            float dc12voltage = ((float) (bit64 & 0xFF)) * 0.1f;//12V蓄电池电压
                                            BigDecimal bigDecimal = new BigDecimal(dc12voltage);
                                            dc12voltage = bigDecimal.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            bcm.setDc12Voltage(dc12voltage);

                                            bit64 = bit64 >> 8;
                                            int errTurnLight = (int) (bit64 & 0x03);//转向灯故障状态
                                            bcm.setErrTurnLight(errTurnLight);

                                            bit64 = bit64 >> 2;
                                            int leftWinOutStatus = (int) (bit64 & 0x03);//左前玻璃升降输出状态
                                            bcm.setLeftWinOutStatus(leftWinOutStatus);

                                            bit64 = bit64 >> 2;
                                            int rightWinOutStatus = (int) (bit64 & 0x03);//右前玻璃升降输出状态
                                            bcm.setRightWinOutStatus(rightWinOutStatus);

                                        } else if (canId == (int) 0x0CFF01DC) {//bcm BCM_SysSt
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BCM_SysSt[0x0CFF01DC]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int backWinIsHeat = (int) (bit64 & 0x01);//后挡风玻璃加热是否开
                                            bcm.setBackWinIsHeat(backWinIsHeat);

                                            bit64 = bit64 >>> 1;
                                            int leftWinStatus = (byte) (bit64 & 0x01);//左窗状态
                                            bcm.setLeftWinStatus(leftWinStatus);
                                            bit64 = bit64 >>> 1;
                                            int rightWinStatus = (byte) (bit64 & 0x01);//右窗错误
                                            bcm.setRightWinStatus(rightWinStatus);
                                            bit64 = bit64 >>> 1;
                                            //reserve
                                            bit64 = bit64 >>> 3;
                                            int isRemoteLightOn = (byte) (bit64 & 0x01);//远光灯是否开
                                            bcm.setIsRemoteLightOn(isRemoteLightOn);
                                            bit64 = bit64 >>> 1;
                                            int isNeerLightOn = (byte) (bit64 & 0x01);//近光灯是否开
                                            bcm.setIsNeerLightOn(isNeerLightOn);
                                            bit64 = bit64 >>> 1;
                                            int isFrontFogOn = (byte) (bit64 & 0x01);//前雾灯是否开
                                            bcm.setIsFrontFogOn(isFrontFogOn);

                                            bit64 = bit64 >>> 1;
                                            int isBackFogOn = (byte) (bit64 & 0x01);//后雾灯是否开
                                            bcm.setIsBackFogOn(isBackFogOn);
                                            bit64 = bit64 >>> 1;
                                            int isDrvLightOn = (byte) (bit64 & 0x01);//昼间行车灯是否开
                                            bcm.setIsDrvLightOn(isDrvLightOn);
                                            bit64 = bit64 >>> 1;
                                            int turnLightStatus = (int) (bit64 & 0x03);//转向灯转向方向
                                            bcm.setTurnLightOn(turnLightStatus);
                                            bit64 = bit64 >>> 2;
                                            // reserve
                                            bit64 = bit64 >>> 2;
                                            int isSmallLightOn = (byte) (bit64 & 0x01);//背光灯（小灯）是否开
                                            bcm.setIsSmallLightOn(isSmallLightOn);
                                            bit64 = bit64 >>> 1;
                                            int isReadLightOn = (byte) (bit64 & 0x01);//室内阅读灯是否开
                                            bcm.setIsReadLightOn(isReadLightOn);
                                            bit64 = bit64 >>> 1;
                                            int isBrakeLightOn = (byte) (bit64 & 0x01);//制动灯是否开
                                            bcm.setIsBrakeLightOn(isBrakeLightOn);
                                            bit64 = bit64 >>> 1;
                                            int isPosLightOn = (byte) (bit64 & 0x01);//位置灯是否开
                                            bcm.setIsPosLightOn(isPosLightOn);
                                            bit64 = bit64 >>> 1;
                                            // reserve
                                            bit64 = bit64 >>> 1;
                                            int isReverseLightOn = (byte) (bit64 & 0x01);//倒车灯是否开
                                            bcm.setIsReadLightOn(isReverseLightOn);
                                            bit64 = bit64 >>> 1;
                                            int alarmStatus = (int) (bit64 & 0x07);//防盗报警状态指示
                                            bcm.setAlarmStatus(alarmStatus);
                                            bit64 = bit64 >>> 3;
                                            // reserve
                                            bit64 = bit64 >>> 1;
                                            int backDoorLockStatus = (byte) (bit64 & 0x01);//后背门锁是否锁止
                                            bcm.setBackDoorLockStatus(backDoorLockStatus);
                                            bit64 = bit64 >>> 1;
                                            int leftDoorLockStatus = (byte) (bit64 & 0x01);//左前门门锁是否锁止
                                            bcm.setLeftDoorLockStatus(leftDoorLockStatus);
                                            bit64 = bit64 >>> 1;
                                            int rightDoorLockStatus = (byte) (bit64 & 0x01);//右前门门锁是否锁止
                                            bcm.setRightDoorLockStatus(rightDoorLockStatus);
                                            bit64 = bit64 >>> 1;
                                            int bcmArmstatus = (byte) (bit64 & 0x01);//
                                            bcm.setBcmArmStatus(bcmArmstatus);
                                            bit64 = bit64 >>> 1;
                                            int bcmEsclpowersupply = (int) (bit64 & 0x03);//
                                            bcm.setBcmEsclPowerSupply(bcmEsclpowersupply);//
                                            bit64 = bit64 >>> 2;
                                            // reserved
                                            bit64 = bit64 >>> 1;
                                            int safetyBeltStatus = (int) (bit64 & 0x03);//安全带是否扣上
                                            bcm.setSafetyBeltStatus(safetyBeltStatus);
                                            bit64 = bit64 >>> 2;
                                            int isLeftDoorClose = (byte) (bit64 & 0x01);//左前门是否关上
                                            bcm.setIsLeftDoorClose(isLeftDoorClose);
                                            bit64 = bit64 >>> 1;
                                            int isRightDoorClose = (byte) (bit64 & 0x01);//右前门是否关上
                                            bcm.setIsRightDoorClose(isRightDoorClose);
                                            bit64 = bit64 >>> 1;
                                            int isEmergecyLightOn = (byte) (bit64 & 0x01);//紧急灯是否开
                                            bcm.setIsEmergecyLightOn(isEmergecyLightOn);
                                            bit64 = bit64 >>> 1;
                                            int wiperStatus = (int) (bit64 & 0x03);//雨刮状态
                                            bcm.setWiperStatus(wiperStatus);
                                            bit64 = bit64 >>> 2;
                                            int isWiperOn = (byte) (bit64 & 0x01);//前雨刮是否开
                                            bcm.setIsWiperStatus(isWiperOn);
                                            bit64 = bit64 >>> 1;
                                            // reserve
                                            bit64 = bit64 >>> 3;
                                            int isFrontHoodOn = (byte) (bit64 & 0x01);//前舱盖是否开
                                            bcm.setIsFrontHoodOn(isFrontHoodOn);
                                            bit64 = bit64 >>> 1;
                                            int isBackDoorOn = (byte) (bit64 & 0x01);//后背门是否开
                                            bcm.setIsBackDoorOn(isBackDoorOn);
                                            bit64 = bit64 >>> 1;
                                            int isHornOn = (byte) (bit64 & 0x01);//喇叭是否开
                                            bcm.setIsHornOn(isHornOn);
                                            bit64 = bit64 >>> 1;
                                            // reserved
                                            bit64 = bit64 >>> 8;
                                            int isKeyVoltageLow = (byte) (bit64 & 0x01);//遥控钥匙电池电量是否低(PEPS指令)
                                            bcm.setIsKeyVoltageLow(isKeyVoltageLow);
                                            bit64 = bit64 >>> 1;
                                            int inbrakeStatus = (int) (bit64 & 0x07);//非法入侵状况
                                            bcm.setIsBrakeStatus(inbrakeStatus);

                                        } else if (canId == (int) 0x18C00501) {//VMS_Info2
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("VMS_Info2[0x18C00501]--->" + ByteBufUtil.hexDump(canBuffer));
                                            bit64 = bit64 >> 16;
                                            int motorStatus = (int) (bit64 & 0x03);//电机当前状态
                                            vms.setMotorStatus(motorStatus);
                                            bit64 = bit64 >> 2;
                                            int isMotorTempHigh = (int) (bit64 & 0x01);//电机温度是否过高
                                            vms.setIsMotorTempHigh(isMotorTempHigh);
                                            bit64 = bit64 >> 1;
                                            int isMotorControlerTempHigh = (int) (bit64 & 0x01);//电机控制器温度是否过高
                                            vms.setIsMotorControlerTempHigh(isMotorControlerTempHigh);
                                            bit64 = bit64 >> 1;
                                            int isMotorControlerErr = (int) (bit64 & 0x01);//电机控制器是否故障
                                            vms.setIsMotorControlerErr(isMotorControlerErr);
                                            bit64 = bit64 >> 1;
                                            int outAlarmInfo = (int) (bit64 & 0x03);//动力输出报警指示
                                            vms.setOutAlarmInfoNumber(outAlarmInfo);
                                        } else if (canId == (int) 0x18C00301) {//VMS_Msg1
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("VMS_Msg1[0x18C00301]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float batteryGroupCurrent = ((float) (bit64 & 0xFFFF) / 10.0f) - 350.0f;//电池组电流
                                            BigDecimal bigDecimal = new BigDecimal(batteryGroupCurrent);
                                            batteryGroupCurrent = bigDecimal.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            vms.setBatteryGroupCurrent(batteryGroupCurrent);

                                            bit64 = bit64 >>> 16;
                                            float batteryGroupVoltage = (float) (bit64 & 0xFF);//电池组电压
                                            vms.setBatteryGroupVoltage(batteryGroupVoltage);
                                            bit64 = bit64 >>> 8;
                                            int leaveBattery = (int) (bit64 & 0xFF);//剩余电量
                                            vms.setLeaveBattery(leaveBattery);
                                            bit64 = bit64 >>> 8;
                                            float speed = (float) (bit64 & 0xFF) * 0.5f;//车速
                                            BigDecimal bigDecimal1 = new BigDecimal(speed);
                                            speed = bigDecimal1.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            vms.setSpeed(speed);
                                            bit64 = bit64 >>> 8;
                                            int motorSysTemp = (int) (bit64 & 0xFF) - 40;//电机系统温度
                                            vms.setMotorSysTemp(motorSysTemp);
                                            bit64 = bit64 >>> 8;
                                            int gearStatus = (int) (bit64 & 0x03);//档位信息
                                            vms.setGearStatus(gearStatus);
                                            bit64 = bit64 >>> 2;
                                            int keyPos = (int) (bit64 & 0x03) & 0xFF;//钥匙位置信息
                                            vms.setKeyPos(keyPos);
                                            bit64 = bit64 >>> 2;
                                            int powerDescStatus = (int) (bit64 & 0x01);//

                                            bit64 = bit64 >>> 1;
                                            int isAirconOpen = (int) (bit64 & 0x01);//空调使能
                                            vms.setIsAirconOpen(isAirconOpen);
                                            bit64 = bit64 >>> 1;
                                            int pepsStatus = (int) (bit64 & 0x01);//PEPS认证状态
                                            vms.setPepsStatus(pepsStatus);
                                            bit64 = bit64 >>> 2;
                                            int isReady = (int) (bit64 & 0xFF);//READY信号
                                            vms.setIsReady(isReady);
                                        } else if (canId == (int) 0x0CF10501) {//
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("[0x0CF10501]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int workType = (int) (bit64 & 0x03);
                                            vms.setWorkType(workType);
                                            bit64 = bit64 >>> 2;
                                            int gear = (int) (bit64 & 0x03);
                                            vms.setGear(gear);
                                            bit64 = bit64 >>> 2;
                                            int brakStatus = (int) (bit64 & 0x03);
                                            vms.setBrakStatus(brakStatus);
                                            bit64 = bit64 >>> 2;
                                            bit64 = bit64 >>> 2;
                                            int deratStatus = (int) (bit64 & 0x03);
                                            vms.setDeratStatus(deratStatus);
                                            bit64 = bit64 >>> 2;
                                            bit64 = bit64 >>> 6;
                                            int keyPosition = (int) (bit64 & 0x03);
                                            vms.setKeyPosition(keyPosition);
                                            bit64 = bit64 >>> 2;
                                            bit64 = bit64 >>> 2;
                                            bit64 = bit64 >>> 12;
                                            int outchargelineConStatus = (int) (bit64 & 0x01);
                                            vms.setOutchargelineConStatus(outchargelineConStatus);
                                            bit64 = bit64 >>> 1;
                                            bit64 = bit64 >>> 1;
                                            bit64 = bit64 >>> 1;
                                            bit64 = bit64 >>> 1;
                                            int tochargeConStatus = (int) (bit64 & 0x01);
                                            vms.setTochargeConStatus(tochargeConStatus);
                                            bit64 = bit64 >>> 1;
                                            bit64 = bit64 >>> 1;
                                            int carType = (int) (bit64 & 0x03);
                                            vms.setCarType(carType);
                                            bit64 = bit64 >>> 2;
                                            int gprsLockCommand = (int) (bit64 & 0x03);
                                            vms.setGprsLockCommand(gprsLockCommand);
                                            bit64 = bit64 >>> 1;
                                            bit64 = bit64 >>> 7;
                                            int vmsSoc = (int) (bit64 & 0xFF);
                                            vms.setVmsSoc(vmsSoc);
                                        } else if (canId == (int) 0x18FF00E0) {//eps EPS_Function
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("EPS_Function[0x18FF00E0]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int errLevel = (int) (bit64 & 0xFF); //EPS 故障等级
                                            eps.setErrLevel(errLevel);
                                            bit64 = bit64 >> 8;
                                            int isWork = (int) (bit64 & 0xFF);//EPS 工作状态
                                            eps.setIsWork(isWork);
                                            bit64 = bit64 >> 8;
                                            float helpMoment = (float) ((bit64 & 0xFFFF)) * 0.1f - 25.0f;//EPS 助力力矩
                                            BigDecimal b1 = new BigDecimal(helpMoment);
                                            helpMoment = b1.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            eps.setHelpMoment(helpMoment);
                                            bit64 = bit64 >> 16;
                                            float electricity = (float) (bit64 & 0xFFFF) * 0.1f;//EPS 电机工作电流
                                            BigDecimal b2 = new BigDecimal(electricity);
                                            electricity = b2.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            eps.setElectricity(electricity);
                                            bit64 = bit64 >> 16;
                                            float voltage = (float) (bit64 & 0xFF) * 0.1f;//电源电压
                                            BigDecimal b3 = new BigDecimal(voltage);
                                            voltage = b3.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            eps.setVoltage(voltage);
                                        } else if (canId == (int) 0x18FF01E0) {//eps EPS_Error
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("EPS_Error[0x18FF01E0]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int isSensorErr = (int) (bit64 & 0x01);//EPS传感器故障
                                            eps.setIsSensorErr(isSensorErr);
                                            bit64 = bit64 >>> 1;
                                            int isCurrentException = (byte) (bit64 & 0x01);//EPS电流异常
                                            eps.setIsCurrentException(isCurrentException);
                                            bit64 = bit64 >>> 1;
                                            int isVoltageHigher = (byte) (bit64 & 0x01);//EPS电压过高
                                            eps.setIsVoltageHigher(isVoltageHigher);
                                            bit64 = bit64 >>> 1;
                                            int isTempHigher = (byte) (bit64 & 0x01);//EPS温度过高
                                            eps.setIsTempHigher(isTempHigher);
                                            bit64 = bit64 >>> 1;
                                            int isVoltageLower = (byte) (bit64 & 0x01);//EPS电压过低
                                            eps.setIsVoltageLower(isVoltageLower);
                                            bit64 = bit64 >>> 1;
                                            int isInitException = (byte) (bit64 & 0x01);//EPS初始化异常
                                            eps.setIsInitException(isInitException);
                                            bit64 = bit64 >>> 1;
                                            int isDriverErr = (byte) (bit64 & 0x01);//EPS电机驱动器故障
                                            eps.setIsDriverErr(isDriverErr);//电机驱动器故障
                                            bit64 = bit64 >>> 1;
                                            int initErr = (byte) (bit64 & 0x01);//电机初始化及轮询故障
                                            eps.setIsMotorInitErr(initErr);
                                            bit64 = bit64 >>> 1;
                                            int angSensorErr = (byte) (bit64 & 0x01);//角度传感器故障
                                            eps.setIsAngleSensorErr(angSensorErr);
                                            bit64 = bit64 >>> 1;
                                            int canEcuErr = (byte) (bit64 & 0x01);//CAN控制器故障
                                            eps.setIsCanCtrlErr(canEcuErr);
                                            bit64 = bit64 >>> 1;
                                            int vspeedSignalEnable = (byte) (bit64 & 0x01);//钥匙位置或车速信号失效
                                            eps.setIsKeyInvalid(vspeedSignalEnable);
                                            bit64 = bit64 >>> 1;
                                            int tempSensorLower = (byte) (bit64 & 0x01);//温度传感器超下限
                                            eps.setIsTempLowerLmt(tempSensorLower);
                                            bit64 = bit64 >>> 1;
                                            int tempSensorHigher = (byte) (bit64 & 0x01);//温度传感器超上限
                                            eps.setIsTempHigher(tempSensorHigher);
                                        } else if (canId == (int) 0x04FF00C8) {//acu ACU_SysSt
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("ACU_SysSt[0x04FF00C8]--->" + ByteBufUtil.hexDump(canBuffer));
                                            bit64 = bit64 >>> 8;
                                            int isCrash = (int) (bit64 & 0x01);//碰撞状态
                                            bit64 = bit64 >>> 1;
                                            int crashPos = (int) (bit64 & 0x7);//碰撞位置
                                            bit64 = bit64 >> 3;
                                            int isGaslightErr = (int) (bit64 & 0x03);//安全气囊故障灯状态

                                        } else if (canId == (int) 0x10FF01DF) {//adas ADAS_Msg1
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("ADAS_Msg1[0x10FF01DF]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int leftLaneDetected = (int) (bit64 & 0x01);//左车道检测
                                            adas.setLeftLaneDetected(leftLaneDetected);
                                            bit64 = bit64 >> 1;
                                            int laneDepartureLeft = (int) (bit64 & 0x01);//车道偏离
                                            adas.setLaneDepartureLeft(laneDepartureLeft);
                                            bit64 = bit64 >> 1;
                                            bit64 = bit64 >> 2;
                                            int rightLaneDetected = (int) (bit64 & 0x01);//右车道检测
                                            adas.setRightLaneDetected(rightLaneDetected);
                                            bit64 = bit64 >> 1;
                                            int laneDepartureRight = (int) (bit64 & 0x01);//车道未偏离
                                            adas.setLaneDpartureRight(laneDepartureRight);
                                            bit64 = bit64 >> 1;
                                            bit64 = bit64 >> 2;
                                            int vehicleDecectResult = (int) (bit64 & 0x01);//车道检测结果
                                            adas.setVehicleDecectResult(vehicleDecectResult);
                                            bit64 = bit64 >> 4;
                                            bit64 = bit64 >> 4;
                                            int crashTime = (int) (bit64 & 0xFF);//碰撞时间
                                            adas.setCrashTime(crashTime);
                                            bit64 = bit64 >> 8;
                                            bit64 = bit64 >> 8;
                                            int error = (int) (bit64 & 0xFF);//错误信息
                                            adas.setErrorInfo(error);
                                            bit64 = bit64 >> 8;
                                            int invalidInfo = (int) (bit64 & 0xFF);//无效信息
                                            adas.setInvalidInfo(invalidInfo);
                                        } else if (canId == (int) 0x18C0EFF4) {//BMS_GPRS_msg1
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BMS_GPRS_msg1[0x18C0EFF4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float totalVoltage = (float) (bit64 & 0xFFFF);//总电压
                                            bms.setTotalVoltage(totalVoltage);
                                            bit64 = bit64 >>> 16;
                                            float totalCurrent = (float) (bit64 & 0xFFFF) * 0.1f - 350.0f;
                                            BigDecimal b1 = new BigDecimal(totalCurrent);
                                            totalCurrent = b1.setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();//总电流
                                            bms.setTotalCurrent(totalCurrent);

                                            bit64 = bit64 >>> 16;
                                            int isChargerConnected = (int) (bit64 & 0x01);//外接充电线连接状态
                                            bms.setIsChargerConnected(isChargerConnected);
                                            bit64 = bit64 >>> 1;
                                            int cpSignal = (int) (bit64 & 0x01);//cp信号
                                            bms.setCpSignal(cpSignal);
                                            bit64 = bit64 >>> 1;
                                            int ksStatus = (int) (bit64 & 0x01);//总负接触器KS状态
                                            bms.setKsStatus(ksStatus);
                                            bit64 = bit64 >>> 1;
                                            int s2Status = (int) (bit64 & 0x01);//
                                            bms.setS2Status(s2Status);
                                            bit64 = bit64 >>> 1;
                                            int isConnectCharger = (int) (bit64 & 0x01);//与充电机通讯状态
                                            bms.setIsConnectCharger(isConnectCharger);
                                            bit64 = bit64 >>> 1;
                                            int isBatteryGroupBalance = (int) (bit64 & 0x01);//电池包均衡状态
                                            bms.setIsBatteryGroupBalance(isBatteryGroupBalance);
                                            bit64 = bit64 >>> 1;
                                            int fanStatus = (int) (bit64 & 0x01);//
                                            bms.setColdFanStatus(fanStatus);

                                            bit64 = bit64 >>> 1;
                                            //reserverd
                                            bit64 = bit64 >>> 1;
                                            int soc = (int) (bit64 & 0xFF);//电池组当前的SOC
                                            bms.setSoc(soc);
                                            bit64 = bit64 >>> 8;
                                            int batteryGroupStatus = (int) (bit64 & 0x03);//电池组当前状态
                                            bms.setBatteryGroupStatus(batteryGroupStatus);
                                            bit64 = bit64 >>> 2;
                                            int errLevel = (int) (bit64 & 0x07);//
                                            bms.setErrorLevel(errLevel);
                                            bit64 = bit64 >>> 3;
                                            int batteryAlarmWarn = (int) (bit64 & 0x01);//
                                            bms.setBatteryAlarmIndication(batteryAlarmWarn);
                                            bit64 = bit64 >>> 1;
                                            int descPowerLevel = (int) (bit64 & 0x03);//
                                            bms.setDescPowerLevel(descPowerLevel);
                                            bit64 = bit64 >>> 2;
                                            // reserved
                                            bit64 = bit64 >>> 6;
                                            int isInsuLowest = (int) (bit64 & 0x01);//绝缘超低
                                            bms.setIsInsuLowest(isInsuLowest);
                                        } else if (canId == (int) 0x18C0EEF4) { //BmsMsg2
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BmsMsg2[0x18C0EEF4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float voltageHighest = (float) ((bit64 & 0xFFFF) * 0.001f);
                                            BigDecimal b1 = new BigDecimal(voltageHighest);
                                            voltageHighest = b1.setScale(3, BigDecimal.ROUND_HALF_UP).floatValue();//最高单体电压
                                            bms.setVoltageHighest(voltageHighest);
                                            bit64 = bit64 >> 16;

                                            int voltageHighestNo = (int) (bit64 & 0xFF);//最高单体电池号
                                            bit64 = bit64 >> 8;
                                            bms.setVoltageHighestNo(voltageHighestNo);

                                            float voltageLowest = (float) ((bit64 & 0xFFFF) * 0.001f);//最低单体电压
                                            BigDecimal b2 = new BigDecimal(voltageLowest);
                                            voltageLowest = b1.setScale(3, BigDecimal.ROUND_HALF_UP).floatValue();
                                            bms.setVoltageLowest(voltageLowest);

                                            bit64 = bit64 >> 16;
                                            int voltageLowestNo = (int) (bit64 & 0xFF);//最低单体电池号
                                            bms.setVoltageHighestNo(voltageHighestNo);

                                            bit64 = bit64 >> 8;
                                            int tempHighest = (int) (bit64 & 0xFF) - 40;//最高温度点温度
                                            bms.setTempHighest(tempHighest);

                                            bit64 = bit64 >> 8;
                                            int tempHighestNo = (int) (bit64 & 0xFF);//最高温度点电池号
                                            bms.setTempHighestNo(tempHighestNo);
                                        } else if (canId == (int) 0x10C000F4) {//单体电压-start-1
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("单体电压[0x10C000F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float voltage1 = (float) ((bit64 & 0x1FF) * 0.01f);//1#单体电池电压
                                            voltage1 = BigDecimal.valueOf(voltage1).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[0] = voltage1;
                                            bit64 = bit64 >> 9;
                                            float voltage2 = (float) ((bit64 & 0x1FF) * 0.01f);//2#单体电池电压
                                            voltage2 = BigDecimal.valueOf(voltage2).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[1] = voltage2;
                                            bit64 = bit64 >> 9;
                                            float voltage3 = (float) ((bit64 & 0x1FF) * 0.01f);//3#单体电池电压
                                            voltage3 = BigDecimal.valueOf(voltage3).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[2] = voltage3;
                                            bit64 = bit64 >> 9;
                                            float voltage4 = (float) ((bit64 & 0x1FF) * 0.01f);//4#单体电池电压
                                            voltage4 = BigDecimal.valueOf(voltage4).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[3] = voltage4;
                                            bit64 = bit64 >> 9;
                                            float voltage5 = (float) ((bit64 & 0x1FF) * 0.01f);//5#单体电池电压
                                            voltage5 = BigDecimal.valueOf(voltage5).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[4] = voltage5;
                                            bit64 = bit64 >> 9;
                                            float voltage6 = (float) ((bit64 & 0x1FF) * 0.01f);//6#单体电池电压
                                            voltage6 = BigDecimal.valueOf(voltage6).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[5] = voltage6;
                                            bit64 = bit64 >> 9;
                                            float voltage7 = (float) ((bit64 & 0x1FF) * 0.01f);//7#单体电池电压
                                            voltage7 = BigDecimal.valueOf(voltage7).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[6] = voltage7;
                                        } else if (canId == (int) 0x14C000F4) {
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("单体电压[0x14C000F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float voltage8 = (float) ((bit64 & 0x1FF) * 0.01f);//8#单体电池电压
                                            voltage8 = BigDecimal.valueOf(voltage8).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[7] = voltage8;
                                            bit64 = bit64 >> 9;
                                            float voltage9 = (float) ((bit64 & 0x1FF) * 0.01f);//9#单体电池电压
                                            voltage9 = BigDecimal.valueOf(voltage9).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[8] = voltage9;
                                            bit64 = bit64 >> 9;
                                            float voltage10 = (float) ((bit64 & 0x1FF) * 0.01f);//10#单体电池电压
                                            voltage10 = BigDecimal.valueOf(voltage10).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[9] = voltage10;
                                            bit64 = bit64 >> 9;
                                            float voltage11 = (float) ((bit64 & 0x1FF) * 0.01f);//11#单体电池电压
                                            voltage11 = BigDecimal.valueOf(voltage11).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[10] = voltage11;
                                            bit64 = bit64 >> 9;
                                            float voltage12 = (float) ((bit64 & 0x1FF) * 0.01f);//12#单体电池电压
                                            voltage12 = BigDecimal.valueOf(voltage12).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[11] = voltage12;
                                            bit64 = bit64 >> 9;
                                            float voltage13 = (float) ((bit64 & 0x1FF) * 0.01f);//13#单体电池电压
                                            voltage13 = BigDecimal.valueOf(voltage13).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[12] = voltage13;
                                            bit64 = bit64 >> 9;
                                            float voltage14 = (float) ((bit64 & 0x1FF) * 0.01f);//14#单体电池电压
                                            voltage14 = BigDecimal.valueOf(voltage14).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[13] = voltage14;
                                        } else if (canId == (int) 0x18C000F4) {
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("单体电压[0x18C000F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float voltage15 = (float) ((bit64 & 0x1FF) * 0.01f);//15#单体电池电压
                                            voltage15 = BigDecimal.valueOf(voltage15).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[14] = voltage15;
                                            bit64 = bit64 >> 9;
                                            float voltage16 = (float) ((bit64 & 0x1FF) * 0.01f);//16#单体电池电压
                                            voltage16 = BigDecimal.valueOf(voltage16).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[15] = voltage16;
                                            bit64 = bit64 >> 9;
                                            float voltage17 = (float) ((bit64 & 0x1FF) * 0.01f);//17#单体电池电压
                                            voltage17 = BigDecimal.valueOf(voltage17).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[16] = voltage17;
                                            bit64 = bit64 >> 9;
                                            float voltage18 = (float) ((bit64 & 0x1FF) * 0.01f);//18#单体电池电压
                                            voltage18 = BigDecimal.valueOf(voltage18).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[17] = voltage18;
                                            bit64 = bit64 >> 9;
                                            float voltage19 = (float) ((bit64 & 0x1FF) * 0.01f);//19#单体电池电压
                                            voltage19 = BigDecimal.valueOf(voltage19).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[18] = voltage19;
                                            bit64 = bit64 >> 9;
                                            float voltage20 = (float) ((bit64 & 0x1FF) * 0.01f);//20#单体电池电压
                                            voltage20 = BigDecimal.valueOf(voltage20).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[19] = voltage20;
                                            bit64 = bit64 >> 9;
                                            float voltage21 = (float) ((bit64 & 0x1FF) * 0.01f);//21#单体电池电压
                                            voltage21 = BigDecimal.valueOf(voltage21).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[20] = voltage21;
                                        } else if (canId == (int) 0x1CC000F4) {
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("单体电压[0x1CC000F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float voltage22 = (float) ((bit64 & 0x1FF) * 0.01f);//22#单体电池电压
                                            voltage22 = BigDecimal.valueOf(voltage22).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[21] = voltage22;
                                            bit64 = bit64 >> 9;
                                            float voltage23 = (float) ((bit64 & 0x1FF) * 0.01f);//23#单体电池电压
                                            voltage23 = BigDecimal.valueOf(voltage23).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[22] = voltage23;
                                            bit64 = bit64 >> 9;
                                            float voltage24 = (float) ((bit64 & 0x1FF) * 0.01f);//24#单体电池电压
                                            voltage24 = BigDecimal.valueOf(voltage24).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[23] = voltage24;
                                            bit64 = bit64 >> 9;
                                            float voltage25 = (float) ((bit64 & 0x1FF) * 0.01f);//25#单体电池电压
                                            voltage25 = BigDecimal.valueOf(voltage25).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[24] = voltage25;
                                            bit64 = bit64 >> 9;
                                            float voltage26 = (float) ((bit64 & 0x1FF) * 0.01f);//26#单体电池电压
                                            voltage26 = BigDecimal.valueOf(voltage26).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[25] = voltage26;
                                            bit64 = bit64 >> 9;
                                            float voltage27 = (float) ((bit64 & 0x1FF) * 0.01f);//27#单体电池电压
                                            voltage27 = BigDecimal.valueOf(voltage27).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[26] = voltage27;
                                            bit64 = bit64 >> 9;
                                            float voltage28 = (float) ((bit64 & 0x1FF) * 0.01f);//28#单体电池电压
                                            voltage28 = BigDecimal.valueOf(voltage28).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[27] = voltage28;
                                        } else if (canId == (int) 0x1CC007F4) {
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("单体电压[0x1CC007F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float voltage29 = (float) ((bit64 & 0x1FF) * 0.01f);//29#单体电池电压
                                            voltage29 = BigDecimal.valueOf(voltage29).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[28] = voltage29;
                                            bit64 = bit64 >> 9;
                                            float voltage30 = (float) ((bit64 & 0x1FF) * 0.01f);//30#单体电池电压
                                            voltage30 = BigDecimal.valueOf(voltage30).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[29] = voltage30;
                                            bit64 = bit64 >> 9;
                                            float voltage31 = (float) ((bit64 & 0x1FF) * 0.01f);//31#单体电池电压
                                            voltage31 = BigDecimal.valueOf(voltage31).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[30] = voltage31;
                                            bit64 = bit64 >> 9;
                                            float voltage32 = (float) ((bit64 & 0x1FF) * 0.01f);//32#单体电池电压
                                            voltage32 = BigDecimal.valueOf(voltage32).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[31] = voltage32;
                                            bit64 = bit64 >> 9;
                                            float voltage33 = (float) ((bit64 & 0x1FF) * 0.01f);//33#单体电池电压
                                            voltage33 = BigDecimal.valueOf(voltage33).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[32] = voltage33;
                                            bit64 = bit64 >> 9;
                                            float voltage34 = (float) ((bit64 & 0x1FF) * 0.01f);//34#单体电池电压
                                            voltage34 = BigDecimal.valueOf(voltage34).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[33] = voltage34;
                                            bit64 = bit64 >> 9;
                                            float voltage35 = (float) ((bit64 & 0x1FF) * 0.01f);//35#单体电池电压
                                            voltage35 = BigDecimal.valueOf(voltage35).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[34] = voltage35;
                                        } else if (canId == (int) 0x1CC008F4) {//单体电压-end-6
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("单体电压[0x1CC008F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float voltage36 = (float) ((bit64 & 0x1FF) * 0.01f);//36#单体电池电压
                                            voltage36 = BigDecimal.valueOf(voltage36).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[35] = voltage36;
                                            bit64 = bit64 >> 9;
                                            float voltage37 = (float) ((bit64 & 0x1FF) * 0.01f);//37#单体电池电压
                                            voltage37 = BigDecimal.valueOf(voltage37).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[36] = voltage37;
                                            bit64 = bit64 >> 9;
                                            float voltage38 = (float) ((bit64 & 0x1FF) * 0.01f);//38#单体电池电压
                                            voltage38 = BigDecimal.valueOf(voltage38).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[37] = voltage38;
                                            bit64 = bit64 >> 9;
                                            float voltage39 = (float) ((bit64 & 0x1FF) * 0.01f);//39#单体电池电压
                                            voltage39 = BigDecimal.valueOf(voltage39).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[38] = voltage39;
                                            bit64 = bit64 >> 9;
                                            float voltage40 = (float) ((bit64 & 0x1FF) * 0.01f);//40#单体电池电压
                                            voltage40 = BigDecimal.valueOf(voltage40).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[39] = voltage40;
                                            bit64 = bit64 >> 9;
                                            float voltage41 = (float) ((bit64 & 0x1FF) * 0.01f);//41#单体电池电压
                                            voltage41 = BigDecimal.valueOf(voltage41).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[40] = voltage41;
                                            bit64 = bit64 >> 9;
                                            float voltage42 = (float) ((bit64 & 0x1FF) * 0.01f);//42#单体电池电压
                                            voltage42 = BigDecimal.valueOf(voltage42).setScale(2, BigDecimal.ROUND_HALF_UP).floatValue();
                                            voltageArray[41] = voltage42;
                                        } else if (canId == (int) 0x18FF05F4) {//BMS_Error
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BMS_Error[0x18FF05F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int sellVoltageHighestChargerL4 = (int) (bit64 & 0x01);//单体电压超高-充电-4级
                                            bms.setSellVolHighestChargerl4(sellVoltageHighestChargerL4);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageHighestFbL3 = (int) (bit64 & 0x01);//单体电压超高-回馈-3级
                                            bms.setSellVolHighestFbl3(sellVoltageHighestFbL3);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageHighestL3 = (int) (bit64 & 0x01);//单体电压超高-3级
                                            bms.setSellVolHighestL3(sellVoltageHighestL3);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageHighestChargerL4 = (int) (bit64 & 0x01);//总电压超高-充电-4级
                                            bms.setTotalVolHighestChargerl4(totalVoltageHighestChargerL4);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageHighestFbL3 = (int) (bit64 & 0x01);//总电压超高-回馈-3级
                                            bms.setTotalVolHighestFbl3(totalVoltageHighestFbL3);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageHighestL3 = (int) (bit64 & 0x01);//总电压超高-3级
                                            bms.setTotalVolHighestl3(totalVoltageHighestL3);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageLowerL1 = (int) (bit64 & 0x01);//单体电压过低-1级降功率
                                            bms.setSellVolLowerl1(sellVoltageLowerL1);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageLowerL2 = (int) (bit64 & 0x01);//单体电压过低-2级降功率
                                            bms.setSellVolLowerl2(sellVoltageLowerL2);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageLowerL3 = (int) (bit64 & 0x01);//单体电压过低-3级降功率
                                            bms.setSellVolLowerl3(sellVoltageLowerL3);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageLowerL1 = (int) (bit64 & 0x01);//总电压过低-1级降功率
                                            bms.setTotalVolLowerl1(totalVoltageLowerL1);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageLowerL2 = (int) (bit64 & 0x01);//总电压过低-2级降功率
                                            bms.setTotalVolLowerl2(totalVoltageLowerL2);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageLowerL3 = (int) (bit64 & 0x01);//总电压过低-3级降功率
                                            bms.setTotalVolLowerl3(totalVoltageHighestL3);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageLowestL3 = (int) (bit64 & 0x01);//单体电压超低-3级
                                            bms.setSellVolLowestl3(sellVoltageLowestL3);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageLowestL4 = (int) (bit64 & 0x01);//单体电压超低-4级
                                            bms.setSellVolLowestl4(sellVoltageLowestL4);
                                            bit64 = bit64 >> 1;
                                            int sellVoltageLowestCharger = (int) (bit64 & 0x01);//单体电压超低-充电
                                            bms.setSellVolLowestCharger(sellVoltageLowestCharger);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageLowestL3 = (int) (bit64 & 0x01);//总电压超低-3级
                                            bms.setTotalVolLowerl3(totalVoltageHighestL3);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageLowestL4 = (int) (bit64 & 0x01);//总电压超低-4级
                                            bms.setTotalVolLowestl4(totalVoltageLowestL4);
                                            bit64 = bit64 >> 1;
                                            int totalVoltageLowestCharger = (int) (bit64 & 0x01);//总电压超低-充电
                                            bms.setTotalVolLowestCharger(totalVoltageLowestCharger);
                                            bit64 = bit64 >> 1;
                                            int voltagePlusBiggerL1 = (int) (bit64 & 0x01);//压差过大-1级降功率
                                            bms.setVolPlusBiggerl1(voltagePlusBiggerL1);
                                            bit64 = bit64 >> 1;
                                            int voltagePlusBiggerL2 = (int) (bit64 & 0x01);//压差过大-2级降功率
                                            bms.setVolPlusBiggerl2(voltagePlusBiggerL2);
                                            bit64 = bit64 >> 1;
                                            int voltagePlusBiggerL3 = (int) (bit64 & 0x01);//压差过大-3级降功率
                                            bms.setVolPlusBiggerl3(voltagePlusBiggerL3);
                                            bit64 = bit64 >> 1;
                                            int socLowerL1 = (int) (bit64 & 0x01);//SOC过低-1级降功率
                                            bms.setSocLowerl1(socLowerL1);
                                            bit64 = bit64 >> 1;
                                            int socLowerL2 = (int) (bit64 & 0x01);//SOC过低-2级降功率
                                            bms.setSocLowerl2(socLowerL2);
                                            bit64 = bit64 >> 1;
                                            int socLowerL3 = (int) (bit64 & 0x01);//SOC过低-3级降功率
                                            bms.setSocLowerl3(socLowerL3);
                                            bit64 = bit64 >> 1;
                                            int dischargerCurrentBiggerL1 = (int) (bit64 & 0x01);//放电电流过大-1级降功率
                                            bms.setDischargerCurrentBiggerl1(dischargerCurrentBiggerL1);
                                            bit64 = bit64 >> 1;
                                            int dischargerCurrentBiggerL2 = (int) (bit64 & 0x01);//放电电流过大-2级降功率
                                            bms.setDischargerCurrentBiggerl2(dischargerCurrentBiggerL2);
                                            bit64 = bit64 >> 1;
                                            int dischargerCurrentBiggerL3 = (int) (bit64 & 0x01);//放电电流过大-3级降功率
                                            bms.setDischargerCurrentBiggerl3(dischargerCurrentBiggerL3);
                                            bit64 = bit64 >> 1;
                                            int dischargerCurrentBiggestL3 = (int) (bit64 & 0x01);//放电电流超大-3级
                                            bms.setDischargerCurrentBiggestl3(dischargerCurrentBiggestL3);
                                            bit64 = bit64 >> 1;
                                            int chargerCurrentBiggestL3 = (int) (bit64 & 0x01);//充电电流超大-3级
                                            bms.setChargerCurrentBiggestl3(chargerCurrentBiggestL3);
                                            bit64 = bit64 >> 1;
                                            int chargerCurrentBiggestL4 = (int) (bit64 & 0x01);//充电电流超大-4级
                                            bms.setChargerCurrentBiggestl4(chargerCurrentBiggestL4);
                                            bit64 = bit64 >> 1;
                                            int feedBackCurrentBiggestL3 = (int) (bit64 & 0x01);//回馈电流超大-3级
                                            bms.setFeedbackCurrentBiggestl3(feedBackCurrentBiggestL3);
                                            bit64 = bit64 >> 1;
                                            int feedBackCurrentBiggestL4 = (int) (bit64 & 0x01);//回馈电流超大-4级
                                            bms.setFeedbackCurrentBiggestl4(feedBackCurrentBiggestL4);
                                            bit64 = bit64 >> 1;
                                            int tempratureHigherL1 = (int) (bit64 & 0x01);//温度过高-1级降功率
                                            bms.setTempratureHigherl1(tempratureHigherL1);
                                            bit64 = bit64 >> 1;
                                            int tempratureHigherL2 = (int) (bit64 & 0x01);//温度过高-2级降功率
                                            bms.setTempratureHigherl2(tempratureHigherL2);
                                            bit64 = bit64 >> 1;
                                            int tempratureHigherL3 = (int) (bit64 & 0x01);//温度过高-3级降功率
                                            bms.setTempratureHigherl3(tempratureHigherL3);
                                            bit64 = bit64 >> 1;
                                            int tempratureHighestL3 = (int) (bit64 & 0x01);//温度超高-3级
                                            bms.setTempratureHigherl3(tempratureHighestL3);
                                            bit64 = bit64 >> 1;
                                            int tempratureHighestL4 = (int) (bit64 & 0x01);//温度超高-4级
                                            bms.setTempratureHighestl4(tempratureHighestL4);
                                            bit64 = bit64 >> 1;
                                            int heatMoTempratureHighest = (int) (bit64 & 0x01);//加热膜温度超高
                                            bms.setHeatMoTempratureHighest(heatMoTempratureHighest);
                                            bit64 = bit64 >> 1;
                                            int tempratureLowerL1 = (int) (bit64 & 0x01);//温度过低-1级降功率
                                            bms.setTempLowerl1(tempratureLowerL1);
                                            bit64 = bit64 >> 1;
                                            int tempratureLowerL2 = (int) (bit64 & 0x01);//温度过低-2级降功率
                                            bms.setTempLowerl2(tempratureHigherL2);
                                            bit64 = bit64 >> 1;
                                            int tempratureLowerL3 = (int) (bit64 & 0x01);//温度过低-3级降功率
                                            bms.setTempLowerl3(tempratureLowerL3);
                                            bit64 = bit64 >> 1;
                                            int tempratureLowestL3 = (int) (bit64 & 0x01);//温度超低-3级
                                            bms.setTempLowestl3(tempratureHighestL3);
                                            bit64 = bit64 >> 1;
                                            int tempraturePlusHigherL1 = (int) (bit64 & 0x01);//温差过高-1级降功率
                                            bms.setTempPlusHigherl1(tempraturePlusHigherL1);
                                            bit64 = bit64 >> 1;
                                            int tempraturePlusHigherL2 = (int) (bit64 & 0x01);//温差过高-2级降功率
                                            bms.setTempPlusHigherl2(tempraturePlusHigherL2);
                                            bit64 = bit64 >> 1;
                                            int tempraturePlusHigherL3 = (int) (bit64 & 0x01);//温差过高-3级降功率
                                            bms.setTempPlusHigherl3(tempraturePlusHigherL3);
                                            bit64 = bit64 >> 1;
                                            int tempratureRiseSpeedBiggerL2 = (int) (bit64 & 0x01);//温升速率过高-2级降功率
                                            bms.setTempRiseSpeedBiggerl2(tempratureRiseSpeedBiggerL2);
                                            bit64 = bit64 >> 1;
                                            int tempratureRiseSpeedBiggestL4 = (int) (bit64 & 0x01);//温升速率超高-4级
                                            bms.setTempRiseSpeedBiggestl4(tempratureRiseSpeedBiggestL4);
                                            bit64 = bit64 >> 1;
                                            int insuLowL1 = (int) (bit64 & 0x01);//绝缘过低-1级
                                            bms.setInsuLowl1(insuLowL1);
                                            bit64 = bit64 >> 1;
                                            int insuLowL2 = (int) (bit64 & 0x01);//绝缘过低-2级降功率
                                            bms.setInsuLowl2(insuLowL2);
                                            bit64 = bit64 >> 1;
                                            int insuLowL4 = (int) (bit64 & 0x01);//绝缘超低-4级
                                            bms.setInsuLowl4(insuLowL4);
                                            bit64 = bit64 >> 1;
                                            int chargeTimeLong = (int) (bit64 & 0x01);//充电时间超长
                                            bms.setChargeTimeLong(chargeTimeLong);
                                            bit64 = bit64 >> 1;
                                            int heatTimeLong = (int) (bit64 & 0x01);//加热时间超长
                                            bms.setHeatTimeLong(heatTimeLong);
                                            bit64 = bit64 >> 1;
                                            int bmsSysErr = (int) (bit64 & 0x01);//BMS系统故障
                                            bms.setBmsSysErr(bmsSysErr);
                                            bit64 = bit64 >> 1;
                                            int chargerNetErr = (int) (bit64 & 0x01);//与充电机通讯故障
                                            bms.setChargerNetErr(chargerNetErr);
                                            bit64 = bit64 >> 1;
                                            int voltageDisconnectL4 = (int) (bit64 & 0x01);//电压采集断开-4级
                                            bms.setVolDisconnectl4(voltageDisconnectL4);
                                            bit64 = bit64 >> 1;
                                            int voltageDisconnectL2 = (int) (bit64 & 0x01);//电压采集断开-2级降功率
                                            bms.setVolDisconnectl2(voltageDisconnectL2);
                                            bit64 = bit64 >> 1;
                                            int tempratureDisconnectL4 = (int) (bit64 & 0x01);//温度采集断开-4级
                                            bms.setTempDisconnectl4(tempratureDisconnectL4);
                                            bit64 = bit64 >> 1;
                                            int tempratureDisconnectL2 = (int) (bit64 & 0x01);//温度采集断开-2级降功率
                                            bms.setTempDisconnectl2(tempratureDisconnectL2);
                                            bit64 = bit64 >> 1;
                                            int heatErr = (int) (bit64 & 0x01);//加热故障
                                            bms.setHeatErr(heatErr);
                                            bit64 = bit64 >> 1;
                                            int negErrClose = (int) (bit64 & 0x01);//负极接触器故障：不能闭合
                                            bms.setNegErrClose(negErrClose);
                                            bit64 = bit64 >> 1;
                                            int negErrPaste = (int) (bit64 & 0x01);//负极接触器故障：粘连
                                            bms.setNegErrPaste(negErrPaste);
                                            bit64 = bit64 >> 1;
                                        } else if (canId == (int) 0x04C000F4) {
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("探头温度[0x04C000F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int temprature1 = (int) (bit64 & 0xFF) - 40;//1#探头温度

                                            tempratureArray[0] = temprature1;
                                            bit64 = bit64 >> 8;
                                            int temprature2 = (int) (bit64 & 0xFF) - 40;//2#探头温度
                                            tempratureArray[1] = temprature2;
                                            bit64 = bit64 >> 8;
                                            int temprature3 = (int) (bit64 & 0xFF) - 40;//3#探头温度
                                            tempratureArray[2] = temprature3;
                                            bit64 = bit64 >> 8;
                                            int temprature4 = (int) (bit64 & 0xFF) - 40;//4#探头温度
                                            tempratureArray[3] = temprature4;
                                            bit64 = bit64 >> 8;
                                            int temprature5 = (int) (bit64 & 0xFF) - 40;//5#探头温度
                                            tempratureArray[4] = temprature5;
                                            bit64 = bit64 >> 8;
                                            int temprature6 = (int) (bit64 & 0xFF) - 40;//6#探头温度
                                            tempratureArray[5] = temprature6;
                                            bit64 = bit64 >> 8;
                                            int temprature7 = (int) (bit64 & 0xFF) - 40;//7#探头温度
                                            tempratureArray[6] = temprature7;
                                            bit64 = bit64 >> 8;
                                            int temprature8 = (int) (bit64 & 0xFF) - 40;//8#探头温度
                                            tempratureArray[7] = temprature8;
                                        } else if (canId == (int) 0x08C000F4) {
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("探头温度[0x08C000F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int temprature9 = (int) (bit64 & 0xFF) - 40;//9#探头温度
                                            tempratureArray[8] = temprature9;
                                            bit64 = bit64 >>> 8;
                                            int temprature10 = (int) (bit64 & 0xFF) - 40;//10#探头温度
                                            tempratureArray[9] = temprature10;
                                            bit64 = bit64 >>> 8;
                                            int temprature11 = (int) (bit64 & 0xFF) - 40;//11#探头温度
                                            tempratureArray[10] = temprature11;
                                            bit64 = bit64 >>> 8;
                                            int temprature12 = (int) (bit64 & 0xFF) - 40;//12#探头温度
                                            tempratureArray[11] = temprature12;
                                            bit64 = bit64 >>> 32;
                                            int bmsError = (int) (bit64 & 0xFF);//BMS故障码
                                            bms.setBmsError(bmsError);

                                        } else if (canId == (int) 0x1806E5F4) {//BMS_charger
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BMS_charger[0x1806E5F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float alowableVoltage = (float) ((bit64 & 0xFFFF) * 0.1f);//最高允许充电端电压
                                            alowableVoltage = BigDecimal.valueOf(alowableVoltage).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            bms.setAlowableVoltage(alowableVoltage);
                                            bit64 = bit64 >>> 16;
                                            float alowableCurrent = (float) ((bit64 & 0xFFFF) * 0.1f);//最高允许充电电流
                                            alowableCurrent = BigDecimal.valueOf(alowableCurrent).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            bms.setAlowableCurrent(alowableCurrent);
                                            bit64 = bit64 >>> 16;
                                            int isableCharge = (int) (bit64 & 0xFF);//

                                            bit64 = bit64 >>> 8;
                                            int loadType = (int) (bit64 & 0x01);//负载类型
                                            bms.setLoadType(loadType);
                                            bit64 = bit64 >>> 1;
                                            int heaterStatus = (int) (bit64 & 0x01);//加热继电器状态
                                            bms.setHeaterStatus(heaterStatus);
                                            bit64 = bit64 >>> 1;
                                            // reserve
                                            bit64 = bit64 >>> 6;
                                            int chargerCount = (int) (bit64 & 0xFFF);//充电次数
                                            bms.setChargerCount(chargerCount);
                                        } else if (canId == (int) 0x18FF01F4) {//BMS_power
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BMS_power[0x18FF01F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int discharge10sPower = (int) (bit64 & 0xFFFF);//动力电池包 10s 最大充电功率
                                            bms.setDischarge10SPower(discharge10sPower);
                                            bit64 = bit64 >> 16;
                                            int discharge30sPower = (int) (bit64 & 0xFFFF);//动力电池包 30s 最大放电功率\
                                            bms.setDischarge30SPower(discharge30sPower);
                                            bit64 = bit64 >> 16;
                                            int dischargeMaximumPower = (int) (bit64 & 0xFFFF);//动力电池包持续最大放电功率
                                            bms.setDischargeMaximumPower(dischargeMaximumPower);
                                            bit64 = bit64 >> 16;
                                            int dischargeMaximumCurrent = (int) (bit64 & 0xFFFF);//动力电池包最大放电电流限值
                                            bms.setDischargeMaximumCurrent(dischargeMaximumCurrent);
                                            bit64 = bit64 >> 16;
                                        } else if (canId == (int) 0x18FF02F4) {//BMS_chargerpower
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("BMS_chargerpower[0x18FF02F4]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int charge10sPower = (int) (bit64 & 0xFFFF);//动力电池包 10s 最大充电功率
                                            bms.setCharge10SPower(charge10sPower);
                                            bit64 = bit64 >> 16;
                                            int charge30sPower = (int) (bit64 & 0xFFFF);//动力电池包 30s 最大充电功率
                                            bms.setCharge30SPower(charge30sPower);
                                            bit64 = bit64 >> 16;
                                            int chargeMaximumPower = (int) (bit64 & 0xFFFF);//动力电池包持续最大充电功率\
                                            bms.setChargeMaximumPower(chargeMaximumPower);
                                            bit64 = bit64 >> 16;
                                            int chargeMaximumCurrent = (int) (bit64 & 0xFFFF) - 350;//动力电池包最大充电电流限值
                                            bms.setChargeMaximumCurrent(chargeMaximumCurrent);
                                            bit64 = bit64 >> 16;
                                        } else if (canId == (int) 0x0CF11F05) {// MC_VMS1
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("MC_VMS1[0x0CF11F05]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int muStatus = (int) (bit64 & 0x03);//电机控制器状态
                                            mc.setMuStatus(muStatus);
                                            bit64 = bit64 >> 2;
                                            int runStatus = (int) (bit64 & 0x03);//电机控制器工作状态
                                            mc.setRunStatus(runStatus);
                                            bit64 = bit64 >> 2;
                                            int temStatus = (int) (bit64 & 0x03);//温度状态
                                            mc.setTemStatus(temStatus);
                                            bit64 = bit64 >> 2;
                                            int voltageStatus = (int) (bit64 & 0x03);//母线电压状态
                                            mc.setVoltageStatus(voltageStatus);
                                            bit64 = bit64 >> 2;
                                            float voltageRange = (float) (bit64 & 0xFF) * 0.5f;//母线电压
                                            voltageRange = BigDecimal.valueOf(voltageRange).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            mc.setVoltageRange(voltageRange);
                                            bit64 = bit64 >> 8;
                                            int motorTemprature = (int) (bit64 & 0xFF) - 40;//电机温度
                                            mc.setMotorTemprature(motorTemprature);
                                            bit64 = bit64 >> 8;
                                            int mcTemprature = (int) (bit64 & 0xFF) - 40;//控制器温度
                                            mc.setMcTemprature(mcTemprature);
                                            bit64 = bit64 >> 8;
                                            int motorRpm = (int) (bit64 & 0xFFFF);//电机转速
                                            mc.setMotorRpm(motorRpm);
                                            bit64 = bit64 >> 16;
                                            float motorCurrent = (float) (bit64 & 0xFFFF) * 0.5f;//电机相电流
                                            motorCurrent = BigDecimal.valueOf(motorCurrent).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            mc.setMotorCurrent(motorCurrent);
                                        } else if (canId == (int) 0x0CF12F05) {// MC_Info1
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("MC_Info1[0x0CF12F05]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int aprRate = (int) (bit64 & 0xFF);//加速踏板开度
                                            mc.setAprRate(aprRate);
                                            bit64 = bit64 >>> 8;
                                            int mcNm = (int) (bit64 & 0xFF) - 120;//电机控制器当前估计扭矩
                                            mc.setMcNm((float) mcNm);
                                            bit64 = bit64 >>> 8;
                                            int busCurrent = (int) (bit64 & 0xFFFF) - 350;//母线电流
                                            mc.setBusCurrent((float) busCurrent);
                                            bit64 = bit64 >>> 16;
                                            int brakeRate = (int) (bit64 & 0xFF);//制动踏板开度
                                            mc.setBrakeRate(brakeRate);
                                            bit64 = bit64 >>> 8;
                                            bit64 = bit64 >>> 2;
                                            int reserver = (int) (bit64 & 0x0F);
                                            bit64 = bit64 >>> 4;
                                            int carType = (int) (bit64 & 0x03);//车型类别
                                            mc.setCarType(carType);
                                            bit64 = bit64 >>> 2;
                                            int isCurrentOut = (int) (bit64 & 0x1);//任一相电流是否过流
                                            mc.setIsCurrentOut(isCurrentOut);
                                            bit64 = bit64 >>> 1;
                                            int isBusCurrentOut = (int) (bit64 & 0x1);//直流母线是否过流
                                            mc.setIsBusCurrentOut(isBusCurrentOut);
                                            bit64 = bit64 >>> 1;
                                            int isMotorRpmOut = (int) (bit64 & 0x1);//电机转速超过限值
                                            mc.setIsMotorRpmOut(isMotorRpmOut);
                                            bit64 = bit64 >>> 1;
                                            int isHolzerErr = (int) (bit64 & 0x1);//霍尔故障
                                            mc.setIsHolzerError(isHolzerErr);
                                            bit64 = bit64 >>> 1;
                                            int isAprErr = (int) (bit64 & 0x1);//加速踏板故障
                                            mc.setIsAprError(isAprErr);
                                            bit64 = bit64 >>> 1;
                                            int isGeerErr = (int) (bit64 & 0x1);//档位输入故障
                                            mc.setIsGeerError(isGeerErr);
                                            bit64 = bit64 >>> 1;
                                            // reserve
                                            bit64 = bit64 >>> 2;
                                            int motorLife = (int) (bit64 & 0xFF);//Life 值
                                            mc.setMotorLife(motorLife);
                                        } else if (canId == (int) 0x0CF13F05) {//MC_Error
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("MC_Error[0x0CF13F05]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int buscurrentSensorError = (int) (bit64 & 0x01);//母线电流传感器故障
                                            mc.setBusCurrentSensorError(buscurrentSensorError);
                                            bit64 = bit64 >>> 1;
                                            int phaseCurrentSensorError = (int) (bit64 & 0x01);//相线电流传感器故障
                                            mc.setPhaseCurrentSensorError(phaseCurrentSensorError);
                                            bit64 = bit64 >>> 1;
                                            int busVolSensorError = (int) (bit64 & 0x01);//母线电压传感器故障
                                            mc.setBusVolSensorError(buscurrentSensorError);
                                            bit64 = bit64 >>> 1;
                                            int controlTempSensorError = (int) (bit64 & 0x01);//控制器温度传感器故障
                                            mc.setControlTempSensorError(controlTempSensorError);
                                            bit64 = bit64 >>> 1;
                                            int mTempSensorError = (int) (bit64 & 0x01);//电机温度传感器故障
                                            mc.setmTempSensorError(mTempSensorError);
                                            bit64 = bit64 >>> 1;
                                            int rotaryTransformerError = (int) (bit64 & 0x01);//旋转变压器故障
                                            mc.setRotaryTransformerError(rotaryTransformerError);
                                            bit64 = bit64 >>> 1;
                                            int controlTempError = (int) (bit64 & 0x01);//控制器温度报警
                                            mc.setControlTempError(controlTempError);
                                            bit64 = bit64 >>> 1;
                                            int controlOuttempError = (int) (bit64 & 0x01);//控制器过温故障
                                            mc.setControlOuttempError(controlOuttempError);
                                            bit64 = bit64 >>> 1;
                                            int mTempAlarm = (int) (bit64 & 0x01);//电机温度报警
                                            mc.setmTempAlarm(mTempAlarm);
                                            bit64 = bit64 >>> 1;
                                            int mOuttempError = (int) (bit64 & 0x01);//电机过温故障
                                            mc.setmOuttempError(mOuttempError);
                                            bit64 = bit64 >>> 1;
                                            int busOutcurrent = (int) (bit64 & 0x01);//母线过流（短路）
                                            mc.setBusOutcurrent(busOutcurrent);
                                            bit64 = bit64 >>> 1;
                                            int busOutvolAlarm = (int) (bit64 & 0x01);//母线过压报警
                                            mc.setBusOutvolAlarm(busOutvolAlarm);
                                            bit64 = bit64 >>> 1;
                                            int busOutvolError = (int) (bit64 & 0x01);//母线过压故障
                                            mc.setBusOutvolError(busOutvolError);
                                            bit64 = bit64 >>> 1;
                                            int busUpdervolAlarm = (int) (bit64 & 0x01);//母线欠压报警
                                            mc.setBusUpdervolAlarm(busUpdervolAlarm);
                                            bit64 = bit64 >>> 1;
                                            int busUpdervolError = (int) (bit64 & 0x01);//母线欠压故障
                                            mc.setBusUpdervolError(busUpdervolError);
                                            bit64 = bit64 >>> 1;
                                            int controlUpdervolError = (int) (bit64 & 0x01);//控制电欠压故障
                                            mc.setControlUpdervolError(controlUpdervolError);
                                            bit64 = bit64 >>> 1;
                                            int controlOutvolError = (int) (bit64 & 0x01);//控制电过压故障
                                            mc.setControlOutvolError(controlOutvolError);
                                            bit64 = bit64 >>> 1;
                                            int phaseOutcurrent = (int) (bit64 & 0x01);//相线过流
                                            mc.setPhaseOutcurrent(phaseOutcurrent);
                                            bit64 = bit64 >>> 1;
                                            int mOutspeedAlarm = (int) (bit64 & 0x01);//电机超速报警
                                            mc.setmOutspeedAlarm(mOutspeedAlarm);
                                            bit64 = bit64 >>> 1;
                                            int mOutspeedError = (int) (bit64 & 0x01);//电机超速故障
                                            mc.setmOutspeedError(mOutspeedError);
                                            bit64 = bit64 >>> 1;
                                            int perchargeError = (int) (bit64 & 0x01);//预充电故障
                                            mc.setPerchargeError(perchargeError);
                                            bit64 = bit64 >>> 1;
                                            int pedalPersamplingError = (int) (bit64 & 0x01);//加速踏板预采样故障
                                            mc.setPedalPersamplingError(pedalPersamplingError);
                                            bit64 = bit64 >>> 1;
                                            int canCommunicatioonError = (int) (bit64 & 0x01);//CAN总线通讯故障
                                            mc.setCanCommunicationError(canCommunicatioonError);
                                            bit64 = bit64 >>> 1;
                                            int errorLevel = (int) (bit64 & 0x07);//故障等级
                                            mc.setErrorLevel(errorLevel);
                                            bit64 = bit64 >>> 3;
                                            int deratingLevel = (int) (bit64 & 0x03);//降功率等级
                                            mc.setDeratingLevel(deratingLevel);
                                            bit64 = bit64 >>> 2;
                                            int powerOutStatus = (int) (bit64 & 0x03);//动力输出状态
                                            mc.setPowerOutStatus(powerOutStatus);
                                            bit64 = bit64 >>> 2;
                                            bit64 = bit64 >>> 26;
                                            String supplierCode = Integer.toBinaryString((int) (bit64 & 0xFF));//供应商配置代码
                                            mc.setSupplierCode(supplierCode);

                                        } else if (canId == (int) 0x18FF50E5) {//obc CHARGER_BMS
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("CHARGER_BMS[0x18FF50E5]--->" + ByteBufUtil.hexDump(canBuffer));
                                            float outVoltage = (float) ((bit64 & 0xFFFF) * 0.1f);//充电机输出电压
                                            outVoltage = BigDecimal.valueOf(outVoltage).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            obc.setOutVoltage(outVoltage);
                                            bit64 = bit64 >> 16;
                                            float outCurrent = (float) ((bit64 & 0xFFFF) * 0.1f);//充电机输出电流
                                            outCurrent = BigDecimal.valueOf(outCurrent).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            obc.setOutCurrent(outCurrent);
                                            bit64 = bit64 >> 16;
                                            int isHardErr = (int) (bit64 & 0x01);//硬件故障
                                            obc.setIsHardErr(isHardErr);
                                            bit64 = bit64 >> 1;
                                            int isTempHirgh = (int) (bit64 & 0x01);//充电机温度状态
                                            obc.setIsTempHigh(isTempHirgh);
                                            bit64 = bit64 >> 1;
                                            int isVoltageErr = (int) (bit64 & 0x01);//输入电压状态
                                            obc.setIsVoltageErr(isVoltageErr);
                                            bit64 = bit64 >> 1;
                                            int isRunning = (int) (bit64 & 0x01);//启动状态
                                            obc.setIsRunning(isRunning);
                                            bit64 = bit64 >> 1;
                                            int isConnected = (int) (bit64 & 0x01);//通信状态
                                            obc.setIsCommected(isConnected);
                                            bit64 = bit64 >> 1;
                                            int isReady = (int) (bit64 & 0x01);//充电准备就绪
                                            obc.setIsReady(isReady);
                                        } else if (canId == (int) 0x18FF51E5) {//obc ObcSt1
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            int inputVoltage = (int) (bit64 & 0x01FF);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("ObcSt1[0x18FF51E5]--->" + ByteBufUtil.hexDump(canBuffer));
                                            obc.setInVoltage((float) inputVoltage);
                                            bit64 = bit64 >> 9;
                                            float inputCurrent = (bit64 & 0x01FF) * 0.1f;
                                            inputCurrent = BigDecimal.valueOf(inputCurrent).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            obc.setInCurrent(inputCurrent);
                                            bit64 = bit64 >> 9;
                                            int pfcVoltage = (int) (bit64 & 0x01FF);
                                            obc.setPfcVoltage((float) pfcVoltage);
                                            bit64 = bit64 >> 9;
                                            // reserve
                                            bit64 = bit64 >> 5;
                                            float dv12Voltage = (bit64 & 0xFF) * 0.1f;
                                            dv12Voltage = BigDecimal.valueOf(dv12Voltage).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            obc.setV12Voltage(dv12Voltage);
                                            bit64 = bit64 >> 8;
                                            float dv12Current = (bit64 & 0x3F) * 0.1f;
                                            dv12Current = BigDecimal.valueOf(dv12Current).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();
                                            obc.setV12Current(dv12Current);
                                            bit64 = bit64 >> 6;
                                            // reserve
                                            bit64 = bit64 >> 2;
                                            float outPowerLevel = (bit64 & 0xFF) * 0.1f;
                                            outPowerLevel = BigDecimal.valueOf(outPowerLevel).setScale(1, BigDecimal.ROUND_HALF_UP).floatValue();

                                            bit64 = bit64 >> 8;
                                            int outCurrentLevel = (int) (bit64 & 0x3F);
                                        } else if (canId == (int) 0x18FF52E5) {//OBC_St2
                                            long bit64 = D2sDataPackUtil.toLong(canBuffer);
                                            //打印调试信息
                                            D2sDataPackUtil.debug("OBC_St2[0x18FF52E5]--->" + ByteBufUtil.hexDump(canBuffer));
                                            int temp1 = (int) ((bit64 & 0xFF) - 50);//温度1
                                            obc.setTemprature1(temp1);
                                            bit64 = bit64 >>> 8;
                                            int temp2 = (int) ((bit64 & 0xFF) - 50);//温度2
                                            obc.setTemprature2(temp2);
                                            bit64 = bit64 >>> 8;
                                            int temp3 = (int) ((bit64 & 0xFF) - 50);//温度3
                                            obc.setTemprature3(temp3);
                                            bit64 = bit64 >>> 8;
                                            int fanStatus = (int) (bit64 & 0x03);//风扇状态
                                            obc.setFanStatus(fanStatus);
                                            bit64 = bit64 >>> 2;
                                            int chargeStatus = (int) (bit64 & 0x03);//充电状态
                                            obc.setChargerStatus(chargeStatus);
                                            bit64 = bit64 >>> 2;
                                            int chargeTempStatus = (int) (bit64 & 0x03);//充电机温度异常监控
                                            obc.setTempratureError(chargeTempStatus);
                                            bit64 = bit64 >>> 2;
                                            bit64 = bit64 >>> 2;
                                            int inputVoltageLow1 = (int) (bit64 & 0x01);//输入欠压1
                                            obc.setInUpdervoltage1(inputVoltageLow1);
                                            bit64 = bit64 >>> 1;
                                            int inputVoltageLow2 = (int) (bit64 & 0x01);//输入欠压2
                                            obc.setInUpdervoltage2(inputVoltageLow2);
                                            bit64 = bit64 >>> 1;
                                            int inputVoltageHigh = (int) (bit64 & 0x01);//输入过压
                                            obc.setInOutvoltage(inputVoltageHigh);
                                            bit64 = bit64 >>> 1;
                                            int outVoltageLow = (int) (bit64 & 0x01);//高压输出欠压
                                            obc.setHighvolOutOutdervol(outVoltageLow);
                                            bit64 = bit64 >>> 1;
                                            int outVoltageHigh = (int) (bit64 & 0x01);//高压输出过压
                                            obc.setHighvolOutOutdervol(outVoltageHigh);
                                            bit64 = bit64 >>> 1;
                                            int outCurrentBig = (int) (bit64 & 0x01);//输出过流
                                            obc.setOutOutcurrent(outCurrentBig);
                                            bit64 = bit64 >>> 2;
                                            int pfcErr = (int) (bit64 & 0x01);//PFC电压异常
                                            obc.setPfcVolError(pfcErr);
                                            bit64 = bit64 >>> 1;
                                            int charger12DcHighErr = (int) (bit64 & 0x01);//充电机12V过压异常
                                            obc.setV12OutvolError(charger12DcHighErr);
                                            bit64 = bit64 >>> 1;
                                            int charger12DcLowErr = (int) (bit64 & 0x01);//充电机12V欠压异常
                                            obc.setV12UpdervolError(charger12DcLowErr);
                                        } else {
                                            System.out.println("Unsupport packet,canId=" + canId + ",buf=" + ByteBufUtil.hexDump(canBuffer));
                                        }
                                    }
                                    /*==========add===========*/
                                    dataPackTargetList.add(new DataPackTarget(hvac));//hvac数据
                                    dataPackTargetList.add(new DataPackTarget(bcm));
                                    //bcm
                                    dataPackTargetList.add(new DataPackTarget(vms));
                                    //vms
                                    dataPackTargetList.add(new DataPackTarget(peps));
                                    //peps
                                    dataPackTargetList.add(new DataPackTarget(eps));
                                    //eps
                                    dataPackTargetList.add(new DataPackTarget(adas));
                                    //adas
                                    bms.setVoltage(voltageArray);// 单体电池电压数组
                                    bms.setTemprature(tempratureArray);// 探头温度数组
                                    dataPackTargetList.add(new DataPackTarget(bms));
                                    //bms
                                    dataPackTargetList.add(new DataPackTarget(obc));
                                    dataPackTargetList.add(new DataPackTarget(mc));

                                    index = index + length;//索引增加
                                } else {
                                    break;
                                }
                            }
                        }
                        break;
                    case 0x05://车辆登出
                        System.out.println("车辆登出");
                        //读取消息头部24个byte
                        buffer.readBytes(24);
                        DataPackLogInOut dataPackLogout = new DataPackLogInOut(dataPackObject);
                        dataPackLogout.setLoginType(1);//设置车辆登录类型为车辆登出
                        //数据采集时间
                        byte[] logOuttimeBuf = new byte[6];
                        buffer.readBytes(logOuttimeBuf);
                        //数据采集时间
                        dataPackObject.setDetectionTime(new Date(D2sDataPackUtil.buf2Date(logOuttimeBuf, 0)));
                        //  dataPackLogout.setReceiveTime(new Date(D2sDataPackUtil.buf2Date(logOuttimeBuf, 0)));
                        //设置车辆vin码
                        //   dataPackLogout.setVin(iccid);
                        //登出流水号
                        int serialNoLogout = D2sDataPackUtil.readInt2(buffer);
                        dataPackLogout.setSerialNo(serialNoLogout);
                        //--add
                        dataPackTargetList.add(new DataPackTarget(dataPackLogout));
                        break;
                    case 0x08://终端校时
                        System.out.println("终端校时");
                        break;
                    case 0x09://车辆告警信息上报
                        System.out.println("## 0x09(预留) - 车辆告警信息上报");
                        //读取消息头部24个byte
                        buffer.readBytes(24);
                        //设置检验时间
                        byte[] alarmtimeBuf = new byte[6];
                        buffer.readBytes(alarmtimeBuf);
                        dataPackObject.setDetectionTime(new Date(D2sDataPackUtil.buf2Date(alarmtimeBuf, 0)));

                        if ((msgLength - 6) == 4 || (msgLength - 6) == 3) {
                            byte alarmId = buffer.readByte();
                            if (alarmId == (byte) 0x02) { //碰撞告警
                                dataPackAlarm = new DataPackAlarm(dataPackObject);
                                List<DataPackAlarm.Alarm> alarmList = new ArrayList<>();
                                //车辆vin码
                                //      dataPackAlarm.setVin(iccid);
                                alarmList.add(new DataPackAlarm.Alarm("automaticActivation", buffer.readByte() & 0xFF, "1：自动报警 2：人工报警"));
                                alarmList.add(new DataPackAlarm.Alarm("testCall", buffer.readByte() & 0xFF, "0：紧急报警 1：呼叫测试"));
                                dataPackAlarm.setAlarmList(alarmList);
                                //--add
                                dataPackTargetList.add(new DataPackTarget(dataPackAlarm));
                            } else if (alarmId == (byte) 0x03) {//拖车告警
                                dataPackAlarm = new DataPackAlarm(dataPackObject);
                                List<DataPackAlarm.Alarm> alarmList = new ArrayList<>();
                                //车辆vin码
                                //     dataPackAlarm.setVin(iccid);
                                //X 轴加速度值：Resolution：0.1；Offset:0；Min:0；Max:25.5；Invalid:0；Unit:m/s2
                                alarmList.add(new DataPackAlarm.Alarm("X-Acceleration", buffer.readByte() & 0xFF, "X轴加速度值"));
                                //Y 轴加速度值：Resolution：0.1；Offset:0；Min:0；Max:25.5；Invalid:0；Unit:m/s2
                                alarmList.add(new DataPackAlarm.Alarm("Y-Acceleration", buffer.readByte() & 0xFF, "Y轴加速度值"));
                                //Z 轴加速度值：Resolution：0.1；Offset:0；Min:0；Max:25.5；Invalid:0；Unit:m/s2
                                alarmList.add(new DataPackAlarm.Alarm("Z-Acceleration", buffer.readByte() & 0xFF, "Z轴加速度值"));
                                dataPackAlarm.setAlarmList(alarmList);
                                //--add
                                dataPackTargetList.add(new DataPackTarget(dataPackAlarm));
                            }
                        }
                        break;
                    case 0x0A://车载终端状态信息上报
                        System.out.println("车载终端状态信息上报");
                        //读取消息头部24个byte
                        buffer.readBytes(24);
                        //设置检验时间
                        byte[] tboxTimeBuf = new byte[6];
                        buffer.readBytes(tboxTimeBuf);
                        dataPackObject.setDetectionTime(new Date(D2sDataPackUtil.buf2Date(tboxTimeBuf, 0)));
                        //包体数据
                        byte[] tboxStatusBuf = new byte[msgLength - 6];
                        buffer.readBytes(tboxStatusBuf);
                        dataPackStatus = new DataPackStatus(dataPackObject);
                        if (tboxStatusBuf != null && tboxStatusBuf.length > 0) {
                            int index = 0;
                            int limit = 0;
                            List<DataPackStatus.Status> statusList = new ArrayList<>();
                            while (index < msgLength && limit++ < 100) {
                                if (tboxStatusBuf[index] == (byte) 0x01) { // 电源状态
                                    statusList.add(new DataPackStatus.Status("电源状态标志", DatatypeConverter.printHexBinary(new byte[]{tboxStatusBuf[index + 1]}), "0：电源故障 1：电源正常"));
                                    index += 2;
                                } else if (tboxStatusBuf[index] == (byte) 0x02) { // 通电状态
                                    statusList.add(new DataPackStatus.Status("通电状态标志", DatatypeConverter.printHexBinary(new byte[]{tboxStatusBuf[index + 1]}), "0：断电 1：通电"));
                                    index += 2;
                                } else if (tboxStatusBuf[index] == (byte) 0x03) { // 通信传输状态
                                    statusList.add(new DataPackStatus.Status("通信传输状态标志", DatatypeConverter.printHexBinary(new byte[]{tboxStatusBuf[index + 1]}), "0：通信传输异常 1：通信传输正常"));
                                    index += 2;
                                } else if (tboxStatusBuf[index] == (byte) 0x80) { // Wifi共享状态
                                    statusList.add(new DataPackStatus.Status("Wifi共享状态", DatatypeConverter.printHexBinary(new byte[]{tboxStatusBuf[index + 1]}), "0：未开启共享 1：开启wifi共享"));
                                    statusList.add(new DataPackStatus.Status("当前共享wifi设备数", DatatypeConverter.printHexBinary(new byte[]{tboxStatusBuf[index + 2]}), "0~255"));
                                    index += 3;
                                } else {
                                    break;
                                }
                            }
                        }
                        //--add
                        dataPackTargetList.add(new DataPackTarget(dataPackStatus));
                        break;
                    case 0x0D://自定义透传数据上报
                        D2sDataPackUtil.debug("=====自定义透传数据上报=====");
                        break;
                    case 0x80://参数查询命令反馈
                        DataPackResult result = new DataPackResult(dataPackObject);
                        if (resId == 1) {//命令执行成功
                            result.setResultName("参数查询成功");
                            //读取消息头部24个byte
                            buffer.readBytes(24);
                            //设置查询参数时间
                            byte[] paramQueryTimeBuf = new byte[6];
                            buffer.readBytes(paramQueryTimeBuf);
                            //参数数量
                            int paramTotal = buffer.readByte();

                            for (int i = 0; i < paramTotal; i++) {
                                //参数ID
                                int paramId = buffer.readByte();
                                //参数长度
                                int paramLength = buffer.readByte();
                                String paramValue;
                                //参数值
                                if (paramId == 0x01 || paramId == 0x02 || paramId == 0x03 || paramId == 0x06 || paramId == 0x0a || paramId == 0x0b || paramId == 0x0f || paramId == 0x82 || paramId == 0x84 || paramId == 0x85 || paramId == 0x86 || paramId == 0x87 || paramId == 0x88 || paramId == 0x89 || paramId == 0x8a || paramId == 0x8b || paramId == 0x8e) {
                                    paramValue = Integer.toString(D2sDataPackUtil.readUInt2(buffer));
                                } else if (paramId == 0x05 || paramId == 0x07 || paramId == 0x08 || paramId == 0x0E || paramId == 0x80 || paramId == 0x81 || paramId == 0x8D) {
                                    byte[] strBuf = new byte[paramLength];
                                    buffer.readBytes(strBuf);
                                    paramValue = new String(strBuf);
                                } else if (paramId == 0x09 || paramId == 0x0c || paramId == 0x10 || paramId == 0x83 || paramId == 0x8f) {
                                    paramValue = Integer.toString(buffer.readByte());
                                }
                            }
                        } else {
                            result.setResultName("参数查询失败");
                        }

                        break;
                    case 0x81://参数设置命令反馈
                        DataPackResult result1 = new DataPackResult(dataPackObject);
                        if (resId == 1) {
                            result1.setResultName("参数设置成功");
                            D2sDataPackUtil.debug("=====参数设置成功！=====");
                        } else {
                            D2sDataPackUtil.debug("=====参数设置失败！=====");
                        }
                        break;
                    case 0x82://车载终端控制命令反馈
                        DataPackResult result2 = new DataPackResult(dataPackObject);
                        if (resId == 1) {
                            result2.setResultName("车载终端控制命令设置成功");
                            D2sDataPackUtil.debug("=====车载终端控制命令执行成功！=====");
                        } else {
                            D2sDataPackUtil.debug("=====车载终端控制命令执行失败！=====");
                        }
                        break;
                    case 0x83://车辆控制命令反馈
                        DataPackResult result3 = new DataPackResult(dataPackObject);
                        //根据resId判断命令是否执行成功
                        if (resId == 1) {
                            result3.setResultName("车辆控制命令执行成功");
                            D2sDataPackUtil.debug("=====车辆控制命令执行成功！=====");
                        } else {
                            D2sDataPackUtil.debug("=====车辆控制命令执行失败！=====");
                        }
                        break;
                    case 0x84://报警参数查询命令反馈
                        DataPackResult result4 = new DataPackResult(dataPackObject);
                        //根据resId判断命令是否执行成功
                        if (resId == 1) {
                            result4.setResultName("报警参数查询命令执行成功");
                            D2sDataPackUtil.debug("=====报警参数查询命令执行成功！=====");
                            //读取消息头部24个byte
                            buffer.readBytes(24);
                            //设置查询参数时间
                            byte[] paramQueryTimeBuf = new byte[6];
                            buffer.readBytes(paramQueryTimeBuf);
                            //参数数量
                            int paramTotal = buffer.readByte();

                            for (int i = 0; i < paramTotal; i++) {
                                //can报文ID
                                int canId = (int) D2sDataPackUtil.readUInt4(buffer);
                                //开始位
                                int start = buffer.readByte();
                                //长度
                                int length = buffer.readByte();
                                //关系 0：等于，1：大于，2，小于
                                int relation = buffer.readByte();
                                //从CAN报文开始位指定长度的信号值
                                int canValue = (int) D2sDataPackUtil.readUInt4(buffer);
                            }
                        } else {
                            D2sDataPackUtil.debug("=====报警参数查询命令执行失败！=====");
                        }
                        break;
                    case 0x85://报警参数设置命令反馈
                        DataPackResult result5 = new DataPackResult(dataPackObject);
                        //根据resId判断命令是否执行成功
                        if (resId == 1) {
                            result5.setResultName("报警参数设置命令执行成功");
                            D2sDataPackUtil.debug("=====报警参数设置命令执行成功！=====");
                        } else {
                            D2sDataPackUtil.debug("=====报警参数设置命令执行失败！=====");
                        }
                        break;
                }
            } catch (Exception e) {
                e.printStackTrace();
            } finally {
                ReferenceCountUtil.release(buffer);
            }
        }
        return dataPackTargetList;
    }

    @Override
    public Map<String, Object> getMetaData(ByteBuf buffer) {
        byte[] dataPackBytes = validate(D2sDataPackUtil.readBytes(buffer, buffer.readableBytes()));
        if (null != dataPackBytes) {
            Map<String, Object> metaDataMap = new HashMap<>();
            // 协议版本
            metaDataMap.put("protocol", PROTOCOL_PREFIX + PROTOCOL_VERSION);
            //获取iccid ICCID 的后 17 位，由 17 位字码构成，字码应符合GB16735 中 4.5 的规定
            String iccid = new String(D2sDataPackUtil.getRange(dataPackBytes, 4, 21));
            metaDataMap.put("iccid", iccid);
            return metaDataMap;
        }
        return null;
    }

}
