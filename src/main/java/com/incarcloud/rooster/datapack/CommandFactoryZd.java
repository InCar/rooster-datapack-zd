package com.incarcloud.rooster.datapack;

import com.incarcloud.rooster.gather.cmd.CommandFactory;
import com.incarcloud.rooster.gather.cmd.CommandType;
import io.netty.buffer.ByteBuf;

/**
 * Created with IntelliJ IDEA.
 * User: chenz
 * Date: 2017/9/5 0005
 * Time: 11:01
 */
public class CommandFactoryZd implements CommandFactory {

    @Override
    public ByteBuf createCommand(CommandType type, Object... args) throws Exception {
        return null;
    }
}
