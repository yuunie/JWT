<?php
namespace Yuunie;

class JWT
{
    protected static $payloadISS;
    protected static $payloadSUB;
    protected static $payloadAUD;
    protected static $payloadEXP;
    protected static $payloadNBF;
    protected static $payloadIAT;
    protected static $payloadJTI;

    protected static $key;

    // 初始化JWT
    protected static function init()
    {
        $nowTime = time();
        // $expTime = 10800;
        // 过期时间
        $expTime = 300;
        // 加密 KEY
        $key = 'JHKAGHKJAHFDSF3SA4B4A45G4ASD4B54A53G46E4G3A5453C4B53AC3B5';

        self::$payloadISS = 'JWT';
        self::$payloadSUB = 'Authorization';
        self::$payloadAUD = 'USER';
        self::$payloadEXP = $nowTime + $expTime;
        self::$payloadNBF = $nowTime;
        self::$payloadIAT = $nowTime;
        self::$payloadJTI = uniqid();
        self::$key = $key;

    }

    // 获得JWT
    /**
     * @name start
     * @static
     * @param array $data 需要保存的数据
     * @param string $key 加密所用KEY
     * @param array $config JWT默认数据
     * @return string
     */
    public static function start($data = [], $key = '', $config = []): String
    {
        // 初始化配置
        self::init();
        if ($key == '') {
            $key = self::$key;
        }
        // 获得头
        $header = self::header();
        // 获得数据
        $payload = self::payload($data, $config);
        // 获得签名
        $signature = self::signature(base64_encode($header), base64_encode($payload), self::$key);
        // 生成JWT
        $jwt = base64_encode($header) . '.' . base64_encode($payload) . '.' . base64_encode($signature);
        // 返回JWT
        return $jwt;
    }

    // 检测JWT
    /**
     * @name check
     * @param string $jwt JWT
     * @param string $key 加密所用的KEY
     * @return int
     */
    public static function check($jwt = '', $key = '')
    {
        if ($key != '') {
            self::setKey($key);
        }
        if ($jwt == '') {
            return 100; // JWT不能为为空
        }
        // 检测JWT格式
        $jwtArray = explode('.', $jwt);
        if (count($jwtArray) != 3) {
            return 101; // JWT格式不完整
        }
        // 检测签名
        $theSignature = $jwtArray[2];
        $checkSignature = self::signature($jwtArray[0], $jwtArray[1], self::$key);
        $checkSignature = base64_encode($checkSignature);
        if ($theSignature != $checkSignature) {
            return 102; // JWT 签名不正确
        }
        // 判断payload是否正常
        $payloadBase = $jwtArray[1];
        $payload = base64_decode($payloadBase);
        $payloadArray = json_decode($payload, true);
        if (!is_array($payloadArray)) {
            return 103; // JWT payload 错误
        }
        // 判断是否启用
        $nowTime = time();
        $nbfTime = $payloadArray['nbf'] ?? '';
        // 判断是否存在启用时间
        if ($nbfTime == '') {
            return 104; // 没有获得启用时间
        }
        if ($nbfTime > $nowTime) {
            return 105; // 当前 JWT 还未启用
        }
        // 判断是否过期
        $expTime = $payloadArray['exp'] ?? '';
        // 判断是否设置过期时间
        if ($expTime == '') {
            return 106; // 没有获取到过期时间
        }
        if ($expTime < $nowTime) {
            return 107; // JWT 过期
        }
        // 判断数据字段是否存在
        if (!isset($payloadArray['dat'])) {
            return 108; // 当前 JWT 中没有数据字段
        }
        return 200;
    }

    // 获得数据
    /**
     * @name get
     * @param string $jwt JWT
     * @param string $name 所需获得的变量名
     * @param bool $check 是否检查 JWT
     * @param string $key 加密所使用 KEY
     * @return mixed
     */
    public static function get($jwt = '', $name = '', $check = true, $key = '') {
        if ($jwt == '') {
            return false;
        }
        if ($name == '') {
            return false;
        }
        if ($check == true) {
            if ($key == '') {
                $key = self::$key;
            }
            if (self::check($jwt, $key) != 200) {
                return false;
            } 
        }
        $jwtArray = explode('.', $jwt);
        $payloadBase = $jwtArray[1];
        $payload = base64_decode($payloadBase);
        $payloadArray = json_decode($payload, true);
        $data = $payloadArray['dat'];
        return $data[$name] ?? false;
    }
    // 获得数据
    /**
     * @name data
     * @param string $jwt JWT
     * @param bool $check 是否检查 JWT
     * @param string $key 加密所使用 KEY
     * @return array
     */
    public static function data($jwt = '', $check = true, $key = '') {
        if ($jwt == '') {
            return false;
        }
        if ($check == true) {
            if ($key == '') {
                $key = self::$key;
            }
            if (self::check($jwt, $key) != 200) {
                return false;
            } 
        }
        $jwtArray = explode('.', $jwt);
        $payloadBase = $jwtArray[1];
        $payload = base64_decode($payloadBase);
        $payloadArray = json_decode($payload, true);
        $data = $payloadArray['dat'];
        return $data ?? false;
    }

    protected static function setKey($key = '') {
        if ($key != '') {
            self::$key = $key;
            return true;
        }
        return false;
    }

    // JWT 头
    protected static function header()
    {
        $algorithm = "RS256";
        $type = "JWT";
        $headerArray = [
            "alg" => $algorithm,
            "typ" => $type,
        ];
        $header = json_encode($headerArray);
        return $header;
    }

    // JWT 数据
    protected static function payload($data = [], $config = [])
    {
        // 发行人
        $iss = $config['iss'] ?? self::$payloadISS;
        // 主题
        $sub = $config['sub'] ?? self::$payloadSUB;
        // 用户
        $aud = $config['aud'] ?? self::$payloadAUD;
        // 到期时间
        $exp = $config['exp'] ?? self::$payloadEXP;
        // 启用时间
        $nbf = $config['nbf'] ?? self::$payloadNBF;
        // 发布时间
        $iat = $config['iat'] ?? self::$payloadIAT;
        // JWT ID
        $jti = $config['jti'] ?? self::$payloadJTI;

        $payloadArray = [
            "iss" => $iss,
            "sub" => $sub,
            "aud" => $aud,
            "exp" => $exp,
            "nbf" => $nbf,
            "iat" => $iat,
            "jti" => $jti,
            "dat" => $data,
        ];
        $payload = json_encode($payloadArray);
        return $payload;
    }

    protected static function signature($headerBase = '', $payloadBase = '', $key = '')
    {
        $data = $headerBase . '.' . $payloadBase;
        // 添加混淆
        $data = $data . $key;
        // 通过RS256生成签名
        $signatureBin = hash('sha256', $data, true);
        $signature = bin2hex($signatureBin);
        return $signature;
    }

}


// 使用以下函数时 需要先配置好 key 等
if (!function_exists('jwt_start')) {
    function jwt_start($data = []) {
        return JWT::start($data);
    }
}
if (!function_exists('jwt_data')) {
    function jwt_data($jwt = '') {
        return JWT::data($jwt);
    }
}