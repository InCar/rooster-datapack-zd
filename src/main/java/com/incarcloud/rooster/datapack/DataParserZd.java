package com.incarcloud.rooster.datapack;

import io.netty.buffer.ByteBuf;

import java.util.List;
import java.util.Map;

/**
 * Created with IntelliJ IDEA.
 * User: chenz
 * Date: 2017/9/5 0005
 * Time: 11:00
 */
public class DataParserZd implements IDataParser {

    @Override
    public List<DataPack> extract(ByteBuf buffer) {
        return null;
    }

    @Override
    public ByteBuf createResponse(DataPack requestPack, ERespReason reason) {
        return null;
    }

    @Override
    public void destroyResponse(ByteBuf responseBuf) {

    }

    @Override
    public List<DataPackTarget> extractBody(DataPack dataPack) {
        return null;
    }

    @Override
    public Map<String, Object> getMetaData(ByteBuf buffer) {
        return null;
    }
}
