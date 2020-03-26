<?php

namespace WeChatApi;

class Common
{
    public static function getIP()
    {
        if (isset($_SERVER)) {
            if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
                $real_ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
            } elseif (isset($_SERVER['HTTP_CLIENT_IP'])) {
                $real_ip = $_SERVER['HTTP_CLIENT_IP'];
            } else {
                $real_ip = $_SERVER['REMOTE_ADDR'];
            }
        } else {
            if (getenv("HTTP_X_FORWARDED_FOR")) {
                $real_ip = getenv("HTTP_X_FORWARDED_FOR");
            } elseif (getenv("HTTP_CLIENT_IP")) {
                $real_ip = getenv("HTTP_CLIENT_IP");
            } else {
                $real_ip = getenv("REMOTE_ADDR");
            }
        }
        return $real_ip;
    }
    /**
     * 微信提交API方法，返回微信指定JSON
     * @param $url
     * @param null $data
     * @return mixed
     */
    public static function curlHttpRequest($url, $data = null)
    {
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, FALSE);
        if (!empty($data)) {
            curl_setopt($curl, CURLOPT_POST, 1);
            curl_setopt($curl, CURLOPT_POSTFIELDS, $data);
        }
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        $output = curl_exec($curl);
        curl_close($curl);
        return $output;
    }

    /**
     * xml post请求 -- 用于退款
     * @param $xml
     * @param $url
     * @param bool $useCert
     * @param int $second
     * @param string $mchid
     * @param string $cert_path
     * @param string $key_path
     * @return bool|string
     */
    public static function postXmlCurl($xml, $url, $useCert = false, $second = 30, $mchid = '', $cert_path = '', $key_path = '')
    {
        $ch = curl_init();
        $curlVersion = curl_version();
        $ua = "WXPaySDK/0.9 (" . PHP_OS . ") PHP/" . PHP_VERSION . " CURL/" . $curlVersion['version'] . " " . $mchid;

        //设置超时
        curl_setopt($ch, CURLOPT_TIMEOUT, $second);

        curl_setopt($ch, CURLOPT_URL, $url);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, TRUE);
        curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 2);//严格校验
        curl_setopt($ch, CURLOPT_USERAGENT, $ua);
        //设置header
        curl_setopt($ch, CURLOPT_HEADER, FALSE);
        //要求结果为字符串且输出到屏幕上
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, TRUE);

        if ($useCert == true) {
            //设置证书
            //使用证书：cert 与 key 分别属于两个.pem文件
            //证书文件请放入服务器的非web目录下
            curl_setopt($ch, CURLOPT_SSLCERTTYPE, 'PEM');
            curl_setopt($ch, CURLOPT_SSLCERT, $cert_path);
            curl_setopt($ch, CURLOPT_SSLKEYTYPE, 'PEM');
            curl_setopt($ch, CURLOPT_SSLKEY, $key_path);

        }
        //post提交方式
        curl_setopt($ch, CURLOPT_POST, TRUE);
        curl_setopt($ch, CURLOPT_POSTFIELDS, $xml);
        //运行curl
        $data = curl_exec($ch);
        //返回结果
        if ($data) {
            curl_close($ch);
            return $data;
        } else {
            $error = curl_errno($ch);
            curl_close($ch);
            return false;
        }
    }

    /**
     * 生成随机字符串 - 最长为32位字符串
     * @param int $length
     * @param bool $type
     * @return string
     */
    public static function genNonceStr($length = 16, $type = false)
    {
        $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        $str = "";
        for ($i = 0; $i < $length; $i++) {
            $str .= substr($chars, mt_rand(0, strlen($chars) - 1), 1);
        }
        if ($type == true) {
            return strtoupper(md5(time() . $str));
        } else {
            return $str;
        }
    }

    /**
     * 生成签名  sha1或者md5签名
     * @param array $data
     * @param string $key 微信支付秘钥
     * @param string $sign_type 签名类型 可选值：md5/sha1
     * @return string
     */
    public static function makeSign($data = [], $key = '', $sign_type = 'md5')
    {
        //签名步骤一：按字典序排序参数
        ksort($data);
        $string = self::genUrlPram($data);
        //签名步骤二：在string后加入KEY
        $string = $string . "&key=" . $key;
        //签名步骤三：MD5加密
        if ($sign_type == 'md5')
            $string = md5($string);
        else
            $string = sha1($string);
        //签名步骤四：所有字符转为大写
        $result = strtoupper($string);
        return $result;
    }

    /**
     * 将数组解析XML
     * @param array $parameters
     * @return string
     */
    public static  function arrayToXml($parameters = [])
    {
        if (!is_array($parameters) || empty($parameters)) {
            die("参数不为数组无法解析");
        }

        $xml = "<xml>";
        foreach ($parameters as $key => $val) {
            if (is_numeric($val)) {
                $xml .= "<" . $key . ">" . $val . "</" . $key . ">";
            } else
                $xml .= "<" . $key . "><![CDATA[" . $val . "]]></" . $key . ">";
        }
        $xml .= "</xml>";
        return $xml;
    }

    /**
     * 将数组解析XML - 多维数组
     * @param array $parameters
     * @return string
     */
    public static function wxMultiArrayToXml($parameters = [])
    {
        if (!is_array($parameters) || empty($parameters)) {
            die("参数不为数组无法解析");
        }

        $xml = "<xml>";
        foreach ($parameters as $key => $val) {
            $xml .= self::xml2($key, $val);
        }
        $xml .= "</xml>";
        return $xml;
    }

    /**
     * 二维数组转xml
     * @param $key
     * @param $value
     * @return string
     */
    public static function xml2($key, $value)
    {
        $xml = '';
        if (is_array($value)) {
            $xml .= "<" . $key . ">";
            foreach ($value as $k => $v) {
                if (is_array($v)) {
                    $xml .= self::xml2($k, $v);
                } else {
                    if (is_numeric($v)) {
                        $xml .= "<" . $k . ">" . $v . "</" . $k . ">";
                    } else {
                        $xml .= "<" . $k . "><![CDATA[" . $v . "]]></" . $k . ">";
                    }
                }

            }
            $xml .= "</" . $key . ">";
        } else {
            if (is_numeric($value)) {
                $xml .= "<" . $key . ">" . $value . "</" . $key . ">";
            } else {
                $xml .= "<" . $key . "><![CDATA[" . $value . "]]></" . $key . ">";
            }
        }
        return $xml;
    }

    /**
     * 微信格式化数组变成参数格式 - 支持url加密
     * @param array $parameters
     * @param bool $urlencode
     * @return string
     */
    public static function genUrlPram($parameters = [], $urlencode = false)
    {
        $param = [];
        ksort($parameters);//排序参数
        foreach ($parameters as $k => $v) { //循环定制参数
            if (null != $v && "null" != $v && "sign" != $k) {
                if ($urlencode) { // 如果参数需要增加URL加密就增加，不需要则不需要
                    $v = urlencode($v);
                }
                $param[] = $k . "=" . $v;//返回完整字符串
            }
        }
        $str = implode('&', $param);
        return $str;//返回字符串
    }

    /**
     * 将XML转为array
     * @param $xml
     * @return mixed
     */
    public static function xmlToArray($xml)
    {
        //禁止引用外部xml实体
        libxml_disable_entity_loader(true);
        $values = json_decode(json_encode(simplexml_load_string($xml, 'SimpleXMLElement', LIBXML_NOCDATA)), true);
        return $values;
    }

}
