package cn.edu.buaa.crypto.utils;

/**
 * Created by Charles on 2017/3/18.
 */

import java.io.UnsupportedEncodingException;

public class Tests {
    public static void main(String args[]) throws UnsupportedEncodingException {
        String a = new String();
        a = "asdawF1244sfjksde++#123m";
        byte x[] = {12, 122, -56, 9, -98};
        System.out.println(x);
        String f = new String(x, "GBK");
        System.out.println(f);


    }
}
