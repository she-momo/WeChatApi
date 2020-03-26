<?php

namespace WeChatApi;


class Config
{
    static $instance = null;
    protected $app_id = '';
    protected $app_secret = '';
    protected $app_id_mini = '';
    protected $app_secret_mini = '';
    protected $mch_id = ''; // 商户号
    protected $pay_api_key = ''; // 支付密钥
    protected $base_url = ''; //根地址
    protected $notify_url = '/notify/wx/payCallback'; // 支付回调地址
    protected $refund_url = '/notify/wx/refundCallback'; // 退款回调地址
    protected $api_client_cert_path = 'cert/apiclient_cert.pem';
    protected $api_client_key_path = 'cert/apiclient_key.pem';

    static public function getInstance() {
        if (is_null(self::$instance))
            self::$instance = new self();

        return self::$instance;
    }

    /**
     * 公众号AppId
     * @return string
     */
    public function getAppId(){
        return $this->app_id;
    }

    /**
     * 公众号AppSecret
     * @return string
     */
    public function getAppSecret()
    {
        return $this->app_secret;
    }

    /**
     * 商户号
     * @return string
     */
    public function getMchId()
    {
        return $this->mch_id;
    }

    /**
     * 小程序AppId
     * @return string
     */
    public function getAppIdMini()
    {
        return $this->app_id_mini;
    }

    /**
     * 小程序AppSecret
     * @return string
     */
    public function getAppSecretMini()
    {
        return $this->app_secret_mini;
    }

    /**
     * 支付密钥
     * @return string
     */
    public function getPayApiKey()
    {
        return $this->pay_api_key;
    }

    /**
     * 项目根地址
     * @return string
     */
    public function getBaseUrl()
    {
        return $this->base_url;
    }

    /**
     * 支付回调地址
     * @return string
     */
    public function getNotifyUrl()
    {
        return $this->notify_url;
    }

    /**
     * 退款回调地址
     * @return string
     */
    public function getRefundUrl()
    {
        return $this->refund_url;
    }

    /**
     * cert证书目录
     * @return string
     */
    public function getApiClientCertPath()
    {
        return $this->api_client_cert_path;
    }

    /**
     * key证书目录
     * @return string
     */
    public function getApiClientKeyPath()
    {
        return $this->api_client_key_path;
    }

}
