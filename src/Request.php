<?php

namespace WeChatApi;


class Request
{
    private $config = null;
    public $parameters = [];
    public $scene = '';

    public function __construct($scene = 'public')
    {
        $this->scene = $scene;
        $this->config = config::getInstance();
    }

    /**
     * 获取app_id
     * @return string
     */
    public function getAppId()
    {
        if ($this->scene == 'public') {
            return $this->config->getAppId();
        } else {
            return $this->config->getAppIdMini();
        }
    }

    /**
     * 获取app_id
     * @return string
     */
    public function getAppSecret()
    {
        if ($this->scene == 'public') {
            return $this->config->getAppSecret();
        } else {
            return $this->config->getAppSecretMini();
        }
    }

    /**
     * 获取AccessToken -- 请求次数有限-- 需自行缓存
     * 公众号调用各接口时都需使用access_token
     * 有效期为7200秒
     * @return mixed
     */
    public function getAccessToken()
    {
        $app_id = $this->getAppId();
        $app_secret = $this->getAppSecret();
        $url = "https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid=" . $app_id . "&secret=" . $app_secret;
        $result = Common::curlHttpRequest($url);;
        $info = json_decode($result, true);
        $access_token = $info["access_token"];
        return $access_token;
    }

    /**
     * 获取sign_package
     * @return array
     */
    public function getSignPackage()
    {
        $js_api_ticket = $this->getJsApiTicket();
        // 注意 URL 一定要动态获取，不能 hardcode.
        $protocol = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off' || $_SERVER['SERVER_PORT'] == 443) ? "https://" : "http://";
        $url = $protocol . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];

        $timestamp = time();
        $nonce_str = Common::genNonceStr();
        // 这里参数的顺序要按照 key 值 ASCII 码升序排序
        $string = "jsapi_ticket=" . $js_api_ticket . "&noncestr=" . $nonce_str . "&timestamp=" . $timestamp . "&url=" . $url;
        $signature = sha1($string);
        $sign_package = [
            "appId" => $this->config->getAppId(),
            "nonceStr" => $nonce_str,
            "timestamp" => $timestamp,
            "url" => $url,
            "signature" => $signature,
            "rawString" => $string
        ];
        return $sign_package;
    }

    /**
     * 获取 ticket -- 请求次数有限-- 需自行缓存
     * 有效期为7200 秒
     * @param string $access_token
     * @return mixed
     */
    private function getJsApiTicket($access_token = '')
    {
        // 如果是企业号用以下 URL 获取 ticket
        // $url = "https://qyapi.weixin.qq.com/cgi-bin/get_jsapi_ticket?access_token=" . $access_token;
        $url = "https://api.weixin.qq.com/cgi-bin/ticket/getticket?type=jsapi&access_token=" . $access_token;
        $res = Common::curlHttpRequest($url);
        $result = json_decode($res);
        $jsapi_ticket = $result->ticket;
        return $jsapi_ticket;
    }

    /**
     * 微信公众号 -- 通过OPENID获取用户信息，返回数组
     * @param string $access_token
     * @param string $openId
     * @return mixed
     */
    public function getUser($openId = '', $access_token = '')
    {
        $url = "https://api.weixin.qq.com/cgi-bin/user/info?access_token=" . $access_token . "&openid=" . $openId . "&lang=zh_CN";
        $result = Common::curlHttpRequest($url);;
        $info = json_decode($result, true);
        return $info;
    }

    /**
     * 微信公众号 -- 获取用户列表，返回数组
     * @param string $next_openid
     * @param string $access_token
     * @return mixed
     */
    public function getUserList($next_openid = '', $access_token = '')
    {
        if (!empty($next_openid)) {
            $next_openid = "&next_openid=NEXT_OPENID";
        }
        $url = "https://api.weixin.qq.com/cgi-bin/user/get?access_token=" . $access_token . $next_openid;
        $result = Common::curlHttpRequest($url);;
        $info = json_decode($result, true);
        return $info;
    }

    /**
     * 微信公众号 -- 获取OPENID 无需用户授权
     * 微信设置OAUTH跳转URL，返回字符串信息 - SCOPE = snsapi_base
     * @param $redirect_url
     * @param string $state
     * @return string
     */
    public function oauthBase($redirect_url, $state = "")
    {
        $app_id = $this->config->getAppId();
        $url = "https://open.weixin.qq.com/connect/oauth2/authorize?appid=" . $app_id . "&redirect_uri=" . urlencode($redirect_url) . "&response_type=code&scope=snsapi_base&state=" . $state . "#wechat_redirect";
        return $url;
    }

    /**
     * 微信公众号 -- 获取用户完整信息 -- 用户授权获取
     * 微信设置OAUTH跳转URL，返回字符串信息 - SCOPE = snsapi_userinfo
     * @param $redirect_url
     * @param string $state
     * @return string
     */
    public function oauthUserInfo($redirect_url, $state = "")
    {
        $app_id = $this->config->getAppId();
        $url = "https://open.weixin.qq.com/connect/oauth2/authorize?appid=" . $app_id . "&redirect_uri=" . $redirect_url . "&response_type=code&scope=snsapi_userinfo&state=" . $state . "#wechat_redirect";
        return $url;
    }

    /**
     * 微信公众号 -- 通过OAUTH返回页面中获取AT信息
     * @param $code
     * @return mixed
     */
    public function oauthAccessToken($code)
    {
        $app_id = $this->config->getAppId();
        $appSecret = $this->config->getAppSecret();
        $url = "https://api.weixin.qq.com/sns/oauth2/access_token?appid=" . $app_id . "&secret=" . $appSecret . "&code=" . $code . "&grant_type=authorization_code";
        $result = Common::curlHttpRequest($url);;
        $return = json_decode($result, true);
        return $return;
    }

    /**
     * 微信公众号 -- 通过OAUTH的Access_Token的信息获取当前用户信息 // 只执行在snsapi_userinfo模式运行
     * @param $oauth_access_token
     * @param $openId
     * @return mixed
     */
    public function wxOauthUser($oauth_access_token, $openId)
    {
        $url = "https://api.weixin.qq.com/sns/userinfo?access_token=" . $oauth_access_token . "&openid=" . $openId . "&lang=zh_CN";
        $result = Common::curlHttpRequest($url);;
        $info = json_decode($result, true);
        return $info;
    }

    /**
     * 微信商户订单号 - 最长28位字符串
     * @return string
     */
    public function wxMchBillNo()
    {
        $mch_id = $this->config->getMchId();
        return date("Ymd", time()) . time() . $mch_id;
    }

    /**
     * 对微信统一下单接口返回的支付相关数据进行处理
     * @param $open_id
     * @param $out_trade_no
     * @param $goods_name
     * @param $total_fee
     * @return array
     */
    public function payment($open_id, $out_trade_no, $goods_name, $total_fee)
    {
        $app_id = $this->getAppId();
        $unified_order = $this->unifiedOrder($app_id, $open_id, $out_trade_no, $goods_name, $total_fee);
        $parameters = [
            'appId' => $app_id,//小程序ID
            'timeStamp' => '' . time() . '',//时间戳
            'nonceStr' => Common::genNonceStr(),//随机串
            'package' => 'prepay_id=' . $unified_order['prepay_id'],//数据包
            'signType' => 'MD5'//签名方式
        ];
        $parameters['paySign'] = Common::makeSign($parameters);
        return $parameters;
    }

    /**
     * 统一下单接口
     * @param $open_id
     * @param $out_trade_no
     * @param $goods_name
     * @param $total_fee
     * @param $app_id
     * @return mixed
     */
    private function unifiedOrder($app_id, $open_id, $out_trade_no, $goods_name, $total_fee)
    {
        $mch_id = $this->config->getMchId();
        $notify_url = $this->config->getNotifyUrl();
        $parameters = [
            'appid' => $app_id, //小程序id
            'mch_id' => $mch_id, //商户id
            'spbill_create_ip' => Common::getIP(), //终端ip
            'notify_url' => $notify_url, //通知地址
            'nonce_str' => Common::genNonceStr(), //随机字符串
            'out_trade_no' => $out_trade_no,//商户订单编号
            'total_fee' => $total_fee * 100, //总金额(分)
            'openid' => $open_id, //用户openid
            'trade_type' => 'JSAPI', //交易类型
            'body' => $goods_name, //商品信息
        ];
        $parameters['sign'] = Common::makeSign($parameters);
        $xml_data = Common::arrayToXml($parameters);
        $xml_result = Common::curlHttpRequest('https://api.mch.weixin.qq.com/pay/unifiedorder', $xml_data);
        $result = Common::xmlToArray($xml_result);
        return $result;
    }

    /**
     * 申请退款
     * @param string $out_trade_no 商户订单编号
     * @param string $out_refund_no 退款单号
     * @param string $total_free 订单金额(分)
     * @param string $refund_fee 退款金额(分)
     * @param int $timeOut
     * @param string $message
     * @return bool|string
     */
    public function refund($out_trade_no = '', $out_refund_no = '', $total_free = '', $refund_fee = '', $timeOut = 6, $message = '商品未出货')
    {
        $app_id = $this->getAppId();
        $refund_url = $this->config->getRefundUrl();
        //检测必填参数
        $parameters = [
            'appid' => $app_id,
            'mch_id' => $this->config->getMchId(), //商户id
            'nonce_str' => Common::genNonceStr(), //随机字符串
            'out_refund_no' => $out_refund_no,
            'refund_fee' => $refund_fee,
            'total_fee' => $total_free,
            'out_trade_no' => $out_trade_no,
            'sign_type' => 'MD5',
            'notify_url' => $refund_url,
            'refund_desc' => $message
        ];
        $parameters['sign'] = Common::makeSign($parameters);
        $xml_data = Common::arrayToXml($parameters);
        $cert_path = $this->config->getApiClientCertPath();
        $key_path = $this->config->getApiClientKeyPath();
        $xml_result = Common::postXmlCurl($xml_data, 'https://api.mch.weixin.qq.com/secapi/pay/refund', true, $timeOut, $cert_path, $key_path);
        return $xml_result;
    }

    /**
     * 查询订单
     * @param string $out_trade_no
     * @return mixed
     */
    public function orderQuery($out_trade_no = '')
    {
        $app_id = $this->getAppId();
        $mchid = $this->config->getMchId();
        $parameters = [
            'appid' => $app_id, //小程序id
            'mch_id' => $mchid, //商户id
            'out_trade_no' => $out_trade_no, //终端ip
            'nonce_str' => Common::genNonceStr(), //随机字符串
        ];
        $parameters['sign'] = Common::makeSign($parameters);
        $xml_data = Common::arrayToXml($parameters);
        $xml_result = Common::curlHttpRequest('https://api.mch.weixin.qq.com/pay/orderquery', $xml_data);
        $result = Common::xmlToArray($xml_result);
        return $result;
    }

    /**
     * 微信公众号 -- 生成二维码ticket
     * @param $data
     * @param $access_token
     * @return mixed
     */
    public function getQrCodeTicket($data = [], $access_token = '')
    {
        $url = "https://api.weixin.qq.com/cgi-bin/qrcode/create?access_token=" . $access_token;
        $result = Common::curlHttpRequest($url, $data);
        return $result;
    }

    /**
     * 微信公众号 -- 通过ticket生成二维码地址
     * @param $ticket
     * @return string
     */
    public function getQrCodeUrl($ticket)
    {
        $url = "https://mp.weixin.qq.com/cgi-bin/showqrcode?ticket=" . urlencode($ticket);
        return $url;
    }

    /**
     * 微信公众号 -- 生成公众号二维码
     * @param string $action_name
     * @param string $scene
     * @param int $expire_seconds
     * @return string
     */
    public function genWxQrCode($action_name = '', $scene = '', $expire_seconds = 0)
    {
        $data['action_name'] = $action_name;
        if (in_array($action_name, ['QR_SCENE', 'QR_LIMIT_SCENE'])) {
            $data['action_info']['scene']['scene_id'] = $scene;
        }
        if (in_array($action_name, ['QR_STR_SCENE', 'QR_LIMIT_SCENE'])) {
            $data['action_info']['scene']['scene_str'] = $scene;
        }
        if (!empty($expire_seconds) && in_array($action_name, ['QR_SCENE', 'QR_STR_SCENE'])) {
            $data['expire_seconds'] = $expire_seconds;
        }
        $ticket_data = $this->getQrCodeTicket(json_encode($data));
        $return = '';
        if (!empty($ticket_data)) {
            $ticket = json_decode($ticket_data, true)['ticket'];
            $return = $this->getQrCodeUrl($ticket);
        }
        return $return;
    }

    /**
     * 微信公众号 -- 获取菜单
     * @param string $access_token
     * @return mixed
     */
    public function getMenu($access_token = '')
    {
        $url = 'https://api.weixin.qq.com/cgi-bin/menu/get?access_token=' . $access_token;
        $result = Common::curlHttpRequest($url);;
        $info = json_decode($result, true);
        return $info;
    }

    /**
     * 微信公众号 -- 生成菜单
     * @param array $menu
     * @param string $access_token
     * @return mixed
     */
    public function createMenu($menu = [], $access_token = '')
    {
        $url = 'https://api.weixin.qq.com/cgi-bin/menu/create?access_token=' . $access_token;
        if (empty($menu)) {
            $menu = [
                'button' => [
                    [
                        'type' => 'miniprogram',
                        'name' => '免费充电',
                        'url' => 'http://mp.weixin.qq.com',
                        'appid' => 'wxfbe9957b929ff18e',
                        'pagepath' => 'pages/index/main',
                        'sub_button' => [],
                    ],
                    [
                        'type' => 'miniprogram',
                        'name' => '扫码泡一杯',
                        'url' => 'http://mp.weixin.qq.com',
                        'appid' => 'wx1964e32178dc854d',
                        'pagepath' => 'pages/index/main?new=1&acid=1',
                        'sub_button' => [],
                    ],
                    [
                        'name' => '运营系统',
                        'sub_button' => [
                            [
                                'type' => 'view',
                                'name' => '我的设备',
                                'url' => 'https://www.zgweiqu.com/index.html'
                            ],
                        ]
                    ]
                ],
            ];
        } else {
            if (is_array($menu)) {
                foreach ($menu['button'] as $key => $val) {
                    if (empty($val)) {
                        unset($menu['button'][$key]);
                    } else {
                        if (isset($val['sub_button']) && !empty($val['sub_button'])) {
                            foreach ($val['sub_button'] as $k => $v) {
                                if (empty($v)) {
                                    unset($menu['button'][$key]['sub_button'][$k]);
                                }
                            }
                        }
                    }
                }
            }
        }
        $menu = json_encode($menu, JSON_UNESCAPED_UNICODE);
        $result = Common::curlHttpRequest($url, $menu);
        $info = json_decode($result, true);
        return $info;
    }

    /**
     * 微信公众号 -- 发送自定义的模板消息
     * 通过指定模板信息发送给指定用户
     * @param $access_token
     * @param $to_user
     * @param $template_id
     * @param $url
     * @param $data
     * @param array $mini_program 小程序
     * @param string $top_color
     * @return mixed
     */
    public function sendTempleMessage($access_token = '', $to_user = '', $template_id = '', $url = '', $data = [], $mini_program = [], $top_color = '#7B68EE')
    {
        $template = [
            'touser' => $to_user,
            'template_id' => $template_id,
            'url' => $url,
            'topcolor' => $top_color,
            'data' => $data
        ];
        if (!empty($mini_program)) {
            $template['miniprogram'] = $mini_program;
        }

        $json_data = json_encode($template);
        $url = "https://api.weixin.qq.com/cgi-bin/message/template/send?access_token=" . $access_token;
        $result = Common::curlHttpRequest($url, $json_data);
        return $result;
    }

    /**
     * 微信公众号 -- 回复文本消息
     * @param $receive
     * @param $content
     * @return string
     */
    public function genTextXmlData($receive, $content)
    {
        $parameters = [
            'ToUserName' => $receive['FromUserName'],
            'FromUserName' => $receive['ToUserName'],
            'CreateTime' => time(),
            'MsgType' => 'text',
            'Content' => str_replace(['\r\n', '\n'], "\r\n", $content)
        ];
        $xml_data = Common::arrayToXml($parameters);
        return $xml_data;
    }

    /**
     * 微信公众号 -- 转发到客服系统
     * @param $receive
     * @return string
     */
    public function genTransferXmlData($receive)
    {
        $parameters = [
            'ToUserName' => $receive['FromUserName'],
            'FromUserName' => $receive['ToUserName'],
            'CreateTime' => time(),
            'MsgType' => 'transfer_customer_service',
        ];
        $xml_data = Common::arrayToXml($parameters);
        return $xml_data;
    }

    /**
     * 微信公众号 -- 回复图片消息
     * @param $receive
     * @param $media_id
     * @return string
     */
    public function genImageXmlData($receive = [], $media_id = 0)
    {
        $parameters = [
            'ToUserName' => $receive['FromUserName'],
            'FromUserName' => $receive['ToUserName'],
            'CreateTime' => time(),
            'MsgType' => 'image',
            'Image' => [
                'MediaId' => $media_id
            ]
        ];
        $xml_data = Common::wxMultiArrayToXml($parameters);
        return $xml_data;
    }

    /**
     * 微信公众号 -- 回复图文消息
     * @param array $receive
     * @param string $title
     * @param string $desc
     * @param string $pic_url
     * @param string $link_url
     * @return string
     */
    public function genNewsXmlData($receive = [], $title = '', $desc = '', $pic_url = '', $link_url = '')
    {
        $parameters = [
            'ToUserName' => $receive['FromUserName'],
            'FromUserName' => $receive['ToUserName'],
            'CreateTime' => time(),
            'MsgType' => 'news',
            'ArticleCount' => 1,
            'Articles' => [
                'item' => [
                    'Title' => $title,
                    'Description' => $desc,
                    'PicUrl' => $pic_url,
                    'Url' => $link_url,
                ]
            ]
        ];
        $xml_data = Common::wxMultiArrayToXml($parameters);
        return $xml_data;
    }

    /**
     * 微信小程序 -- 生成小程序二维码A
     * 接口A: 适用于需要的码数量较少的业务场景
     * 接口A加上接口C，总共生成的码数量限制为100,000，请谨慎调用。
     * @param array $data
     * @param string $access_token
     * @return mixed
     */
    public function genMiniProgramQrCodeA($data = [], $access_token = '')
    {
        $url = 'https://api.weixin.qq.com/wxa/getwxacode?access_token=' . $access_token;
        $data = [
            'path' => 'pages/index/main?mid=' . $data,
            'width' => 430
        ];
        $json_data = json_encode($data);
        $result = Common::curlHttpRequest($url, $json_data);
        return $result;
    }

    /**
     * 微信小程序 -- 生成小程序二维码B
     * 接口B 通过该接口生成的小程序码，永久有效，数量暂无限制。
     * @param array $data
     * @param string $access_token
     * @return mixed
     */
    public function genMiniProgramQrCodeB($data = [], $access_token = '')
    {
        $url = 'https://api.weixin.qq.com/wxa/getwxacodeunlimit?access_token=' . $access_token;
        $data = [
            'scene' => 'mid=' . $data, // 最大32个可见字符，只支持数字，大小写英文以及部分特殊字符：!#$&'()*+,/:;=?@-._~
            'page' => 'pages/index/main', // 必须是已经发布的小程序页面，例如 "pages/index/index" ,如果不填写这个字段，默认跳主页面
            'width' => 430, // 二维码的宽度
            'auto_color' => true,
            'line_color' => '{"r":"0","g":"0","b":"0"}', // auto_color 为 false 时生效，使用 rgb 设置颜色 例如 {"r":"xxx","g":"xxx","b":"xxx"}
            'is_hyaline' => false
        ];
        $json_data = json_encode($data);
        $result = Common::curlHttpRequest($url, $json_data);
        return $result;
    }

    /**
     * 微信小程序 -- 生成小程序二维码C
     * 适用于需要的码数量较少的业务场景
     * 接口A加上接口C，总共生成的码数量限制为100,000，请谨慎调用。
     * @param array $data
     * @param string $access_token
     * @return mixed
     */
    public function genMiniProgramQrCodeC($data = [], $access_token = '')
    {
        $url = 'https://api.weixin.qq.com/cgi-bin/wxaapp/createwxaqrcode?access_token=' . $access_token;
        $data = [
            'path' => 'pages/index/main?mid=' . $data, // 不能为空，最大长度 128 字节
            'width' => 430
        ];
        $json_data = json_encode($data);
        $result = Common::curlHttpRequest($url, $json_data);
        return $result;
    }
}
