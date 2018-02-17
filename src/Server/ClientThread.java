package Server;

import PSN_New.TokenMessage1;
import stu.edu.cn.zing.voicechat.MyMessage1;

import java.io.EOFException;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Created by Administrator on 2016/9/10.
 */
public class ClientThread extends Thread {

    private int threadNum=1;

    private String user = "";  //连接上的客户端的用于聊天的名称
    private Socket socket = null;
    private ServerThread serverThread = null;
    private ObjectOutputStream oos = null;
    private ObjectInputStream ois = null;

    private boolean tokensend = false;
    private TokenMessage1 tokenMessage1;

    private String ip = ""; //客户端ip地址

    private boolean threadStop = true; //用来控制线程结束的标志

    private LinkedBlockingQueue<MyMessage1> msgQueue = null; //服务器的接收队列
    private LinkedBlockingQueue<MyMessage1> sendQueue = null; //客户端自己的发送队列

    private Thread sendThread = null; //用于发送消息的线程

    /**
     * 构造犯法
     *
     * @param socket       连接到服务器的Socket
     * @param msgQueue     服务器的接收消息队列
     * @param sendQueue    客户端自己的发送消息队列
     * @param serverThread 服务器线程
     */
    public ClientThread(Socket socket, LinkedBlockingQueue<MyMessage1> msgQueue, LinkedBlockingQueue<MyMessage1> sendQueue,
                        TokenMessage1 tokenMessage1, ServerThread serverThread) {

        System.out.println();
        this.socket = socket;
        this.msgQueue = msgQueue;
        this.sendQueue = sendQueue;
        this.tokenMessage1 = tokenMessage1;
        this.serverThread = serverThread;
        ip = socket.getInetAddress().toString();

        try {

            oos = new ObjectOutputStream(socket.getOutputStream());
            ois = new ObjectInputStream(socket.getInputStream());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    @Override
    public void run() {
        System.out.println("客户端：" + socket.getInetAddress().toString() + "线程启动");


        //启动发送消息线程
        runSend();

        //接收消息
        try {
            while (threadStop) { //这里一个是 while (threadStop) 下面的 runSend() 是 while (!isInterrupted())
                //put方法会在队列满时阻塞
                MyMessage1 myMessage1 = (MyMessage1) ois.readObject();
                /***********
                 * @Author: Charles_Wu
                 * @Data: 13:33 2018/1/2
                 * @Description: 从流中读取 MyMessage1 对象
                 ****************************************/
                msgQueue.put(myMessage1);
//                if (myMessage1.getMsgType() == MyMessage.MSG_AUDIO_MARK
//                        && myMessage1.getMessage().equals("start")) { //收到语音文件开始标志
//                    //下面这段代码可以锁住服务器队列msgQueue来保证消息的连贯（这里可以用更好的方法，不用保证消息的连贯）
//                    while (true) {
//                        MyMessage1 myMessage1 = (MyMessage1) ois.readObject();
//                        if (myMessage1.getMsgType() == MyMessage.MSG_AUDIO_MARK
//                                && myMessage1.getMsgContent().equals("end")) { //收到语音文件结束标志，退出循环
//                            msgQueue.put(myMessage1);
//                            break;
//                        }
//                        msgQueue.put(myMessage1);
//                        /***********
//                         * @Author: Charles_Wu
//                         * @Data: 13:37 2018/1/2
//                         * @Description: 用 start 和 end 作为语音对象接收的开始和结束
//                         ****************************************/
//                    }
//                }
            }
        } catch (EOFException e) {
            //当客户端退出连接，即socket关闭，捕获这异常，在这里结束负责与客户端连接的客户端线程
            threadStop = false;
            serverThread.clientThreads.remove(this);
            sendThread.interrupt(); //发送中断，结束 sendThread 线程
            System.out.println("客户端：" + ip + "已退出");
        } catch (IOException e) {
            e.printStackTrace();
        } catch (InterruptedException e) {
            e.printStackTrace();
        } catch (ClassNotFoundException e) {
            e.printStackTrace();
        } finally {
            try {
                if (oos != null) {
                    oos.close();
                }
                if (ois != null) {
                    ois.close();
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
        System.out.println("客户端：" + ip + "接收消息线程结束");
    }


    /**
     * 启动线程从队列中拿出消息进行发送
     */
    private void runSend() {
        sendThread = new Thread(new Runnable() {
            @Override
            public void run() {
                if (!tokensend) {
                    try {
                        /***********
                         * @Author: Charles_Wu
                         * @Data: 16:53 2018/1/4
                         * @Description: 转换为字节再发送
                         ****************************************/

//                    byte[] byteArrayTokenMessage = TestUtils.SerCipherParameter(tokenMessage);
                        oos.writeObject(tokenMessage1);
//                    oos.flush();
                        tokensend = true;
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }
                while (!isInterrupted()) {
                    try {
                        //若队列中没有数据take()方法会阻塞住
                        System.out.println("客户端：" + ip + "等待需要发送的消息");
                        MyMessage1 myMessage1 = sendQueue.take();
                        int msgType = myMessage1.getMsgType();
                        String content = myMessage1.getMessage();

                        System.out.println("客户端：" + ip + "取出需要发送的消息，消息类型；" + msgType);

                        if (msgType == MyMessage1.MSG_LOGIN) { //登录，记录下登录的名称
                            user = content;
                            myMessage1.setMessage(content + "加入聊天");
                            System.out.println("客户端：" + ip + "用户" + user + "登录");
                        }
                        myMessage1.setSendName(user);
                        oos.writeObject(myMessage1);
                    } catch (InterruptedException e) {
                        break;
                    } catch (IOException e) {
                        e.printStackTrace();
                    }
                }

                System.out.println("客户端：" + ip + "发送消息线程结束");
            }
        });
        sendThread.start();
    }
}
