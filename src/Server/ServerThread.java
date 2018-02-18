package Server;

import PSN_New.MyMessageSign;
import PSN_New.PSNSigningEngine;
import PSN_New.TokenMessage1;
import stu.edu.cn.zing.voicechat.MyMessage1;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.LinkedBlockingQueue;

/**
 * Created by Administrator on 2016/9/10.
 */
public class ServerThread extends Thread {

    private ServerSocket serverSocket = null;

    private LinkedBlockingQueue<MyMessage1> msgQueue = null; //服务器的消息队列

    private List<String> hostAddress = null; //记录客户端的ip地址与客户端消息队列相对应

    private List<LinkedBlockingQueue<MyMessage1>> sendQueues = null; //客户端的消息队列用于发送消息

    public List<ClientThread> clientThreads = null; //已连接的客户端列表，（ClientThread 为 自写类）

    //构造方法
    public ServerThread(ServerSocket serverSocket) {
        this.serverSocket = serverSocket;
        clientThreads = new ArrayList<ClientThread>();
        msgQueue = new LinkedBlockingQueue<MyMessage1>(100);
        hostAddress = new ArrayList<String>();
        sendQueues = new ArrayList<LinkedBlockingQueue<MyMessage1>>();
    }

    @Override
    public void run() {
        runReceive();
        System.out.println("服务器线程启动.");
        System.out.println("等待客户端连接...");
        while (true) {
            try {
                /*
                 *accept() 方法会在等待客户端Socket连接时闲置，
                 *所以用while(true)循环一直等待客户端连接，
                 *客户端连接时该方法会返回一个用于通讯的Socket
                 */
                final Socket socket = serverSocket.accept();
                String ip = socket.getInetAddress().toString();
                System.out.println("客户端：" + ip + "连接上服务器");
                LinkedBlockingQueue<MyMessage1> sendQueue;
                PSNSigningEngine psnSigningEngine = new PSNSigningEngine();
                TokenMessage1 tokenMessage1 = psnSigningEngine.generateTokenMessage();
                //检查该客户端是否登陆过，是的话将之前的消息队列传给他，不是就新建一个消息队列
                if (!hostAddress.contains(ip)) {
                    hostAddress.add(ip);
                    sendQueue = new LinkedBlockingQueue<MyMessage1>(100);
                    sendQueues.add(sendQueue);
                    //第一遍加入 sendQueues的 sendQueue 不包含任何 myMessage
                } else {
                    sendQueue = sendQueues.get(hostAddress.indexOf(ip));
                }

                ClientThread clientThread = new ClientThread(socket, msgQueue, sendQueue, tokenMessage1, this);
                clientThread.start();

                //将客户端添加进列表中
                clientThreads.add(clientThread);
                System.out.println("当前客户端个数：" + clientThreads.size());

            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     * 启动线程从队列中拿出消息进行处理 只启动了一次
     */
    private void runReceive() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                while (true) {
                    try {
                        System.out.println("服务器等待取出消息...");
                        MyMessage1 myMessage1 = (MyMessage1) msgQueue.take();
                        if (myMessage1.getAuth()) {
                            MyMessageSign myMessageSign = new MyMessageSign();
                            myMessageSign.init();
                            myMessageSign.generatePublicKey(myMessage1.getgBytes(), myMessage1.getQBytes(),
                                    myMessage1.getByteArrayU1(), myMessage1.getByteArrayU2());
                            if (myMessageSign.verifySignature(myMessage1.getMessage().getBytes(), myMessage1.getSiganature()) == true) {
                                System.out.println("服务器取出消息，消息类型：" + myMessage1.getMsgType());
                                String message = myMessage1.getMessage();
                                System.out.println(message);
                                System.out.println("消息签名认证通过！");
                            } else {
                                System.out.println("服务器取出消息，消息类型：" + myMessage1.getMsgType());
                                System.out.println("消息签名认证未通过！");
                            }
                        } else {

                        }

                        //直到 msgQueue 中的 MyMessage 被取空，take()会被阻塞住
//                        System.out.println("服务器取出消息，消息类型：" + myMessage1.getMsgType());
//                        int msgType = myMessage1.getMsgType();
//                        String sendName = myMessage1.getSendName();
//                        String message = myMessage1.getMessage();
//                        System.out.println(message);
                        //将消息发送到客户端线程
                        //只有将消息 myMessage 从 msgQueue中取出，再塞进 sendQueues,客户端线程才能取出有用的 myMessage 再发送出去发送出去
//                        在这里是给sendQueues里的每个 sendQueue 填充信息
                        for (int i = 0; i < sendQueues.size(); i++) {
                            sendQueues.get(i).put(myMessage1);
                        }
                    } catch (InterruptedException e) {
                        e.printStackTrace();
                    }
                }
            }
        }).start();
    }
}
