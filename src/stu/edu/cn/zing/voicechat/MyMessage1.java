package stu.edu.cn.zing.voicechat;

import PSN_New.PSNSignPublicKeySerParameter;
import org.bouncycastle.crypto.CipherParameters;

import java.io.Serializable;

public class MyMessage1 implements CipherParameters, Serializable {

    private int msgType = -1;
    private String sendName = "";
    private String message = "";
    private byte[] messageBytes;
    private byte[] siganature;
    //    private transient PSNSignPub  licKeySerParameter publicKey;//比较担心这个能不能序列化
    private byte[] gBytes;
    private byte[] QBytes;
    private byte[] byteArrayU1;
    private byte[] byteArrayU2;

    public boolean Auth = false;
    public static final int MSG_AUDIO = 1; //消息类型，语音消息
    public static final int MSG_LOGIN = 2; //消息类型，登录消息
    public static final int MSG_TEXT = 3; //消息类型，文本消息
    public static final int MSG_AUDIO_MARK = 4;
    public static final int MSG_SIGN = 5;// 消息类型，语音消息的标识
    public static final int MSG_Token = 6;

    public MyMessage1(int msgType, String msgContent) {
        this.msgType = msgType;
        this.message = msgContent;
    }

    public MyMessage1() {

    }

    public void setAuth() {
        this.Auth = true;
    }

    public void setMsgType(int msgType) {
        this.msgType = msgType;
    }

    public void setSendName(String sendName) {
        this.sendName = sendName;
    }

    public void setMessageBytes(String message) {
        this.messageBytes = message.getBytes();
    }

    public void setMessage(String message) {
        this.message = message;
    }

    public void setSiganature(byte[] siganature) {
        this.siganature = siganature;
    }

    //    public void setPublicKey(PairingKeySerParameter publicKey){this.publicKey = publicKey;}
    public void setpublickey(PSNSignPublicKeySerParameter publicKey) {
        this.gBytes = publicKey.getByteArrayG();
        this.QBytes = publicKey.getByteArrayQ();
        this.byteArrayU1 = publicKey.getByteArrayU1();
        this.byteArrayU2 = publicKey.getByteArrayU2();
    }

    public boolean getAuth() {
        return Auth;
    }

    public int getMsgType() {
        return msgType;
    }

    public String getSendName() {
        return sendName;
    }

    public String getMessage() {
        return message;
    }

    public byte[] getMessageBytes() {
        return messageBytes;
    }

    public byte[] getSiganature() {
        return siganature;
    }

    public byte[] getgBytes() {
        return gBytes;
    }

    public byte[] getQBytes() {
        return QBytes;
    }

    public byte[] getByteArrayU1() {
        return byteArrayU1;
    }

    public byte[] getByteArrayU2() {
        return byteArrayU2;
    }

    //    public PairingKeySerParameter getPublicKey(){ return publicKey;}


}
