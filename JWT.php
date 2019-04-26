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

    protected static function base64_encode_good($data)
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    // 初始化JWT
    protected static function init()
    {
        $nowTime = time();
        // $expTime = 10800;
        // 过期时间
        $expTime = 300;
        // 加密 KEY
        // HS256 256位字符串 保障JWT签名安全
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
     * 获得JWT
     *
     * @name start
     * @static
     * @param array $data 需要保存的数据(可选,不填为空)
     * @param string $key 加密所用KEY(可选,不填使用默认配置的KEY)
     * @param array $config JWT默认数据(可选,不填使用默认配置的JWT PAYLOAD)
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
        $signature = self::signature(self::base64_encode_good($header), self::base64_encode_good($payload), self::$key);
        // 生成JWT
        $jwt = self::base64_encode_good($header) . '.' . self::base64_encode_good($payload) . '.' . self::base64_encode_good($signature);
        // 返回JWT
        return $jwt;
    }

    // 检测JWT
    /**
     * 检测JWT
     * @name check
     * @param string $jwt JWT
     * @param string $key 加密所用的KEY(可选,不填使用默认配置的KEY)
     * @return int
     */
    public static function check($jwt = '', $key = '')
    {
        self::init();
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
        $checkSignature = self::base64_encode_good($checkSignature);
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
     * 获得数据
     *
     * @name get
     * @param string $jwt JWT
     * @param string $name 所需获得的变量名
     * @param bool $check 是否检查 JWT (可选)(true,false)
     * @param string $key 加密所使用 KEY(可选,不填使用默认配置的KEY)
     * @return mixed
     */
    public static function get($jwt = '', $name = '', $check = true, $key = '')
    {
        self::init();
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

    // 为已经存在的JWT 添加或更改数据
    /**
     * 为JWT添加修改数据
     *
     * @name set
     * @param string $jwt JWT
     * @param array $data 需要添加或修改的值(数组键值对)
     * @return string
     */
    public static function set($jwt = '', $data = [])
    {
        $jwtData = self::data($jwt);
        $newData = @array_merge($jwtData, $data);
        return self::start($newData);
    }
    // 获得数据
    /**
     * @name data
     * @param string $jwt JWT
     * @param bool $check 是否检查 JWT (可选)(true,false)
     * @param string $key 加密所使用 KEY (可选,不填使用默认配置的KEY)
     * @return array
     */
    public static function data($jwt = '', $check = true, $key = '')
    {
        self::init();
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

    /**
     * 设置JWT 默认 加密秘钥
     *
     * @name setKey
     * @param string $key 加密秘钥(尽量复杂,用于包含JWT,请勿泄露)
     * @return bool
     */
    public static function setKey($key = '')
    {
        if ($key != '') {
            self::$key = $key;
            return true;
        }
        return false;
    }

    // JWT 头
    protected static function header()
    {
        $algorithm = "HS256";
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

    // 签名
    protected static function signature($headerBase = '', $payloadBase = '', $key = '')
    {
        $data = $headerBase . '.' . $payloadBase;
        // 添加混淆
        $data = $data . $key;
        // 通过S256生成签名
        $signatureBin = hash('sha256', $data, true);
        $signature = bin2hex($signatureBin);
        return $signature;
    }

}

// 使用以下函数时 需要先配置好 key 等
if (!function_exists('jwt_start')) {
    /**
     * 创建一个JWT并添加用户数据
     *
     * @param array $data 存入JWT中的数据(可选)
     */
    function jwt_start($data = [])
    {
        return JWT::start($data);
    }
}
if (!function_exists('jwt_set')) {
    /**
     * 修改或添加JWT中的用户数据
     *
     * @param string $jwt JWT
     * @param array $data 需要更改或替换的数据(数组键值对)
     */
    function jwt_set($jwt = '', $data = [])
    {
        return JWT::set($jwt, $data);
    }
}
if (!function_exists('jwt_get')) {
    /**
     * 获取JWT中指定的用户设置的数据
     *
     * @param string $jwt JWT
     * @param string $name 字段名
     */
    function jwt_get($jwt = '', $name = '')
    {
        return JWT::get($jwt, $name);
    }
}
if (!function_exists('jwt_data')) {
    /**
     * 获取JWT中所有用户设置的数据
     *
     * @param string $jwt JWT
     */
    function jwt_data($jwt = '')
    {
        return JWT::data($jwt);
    }
}
if (!function_exists('jwt_check')) {
    /**
     * 检测JWT
     *
     * @param string $jwt JWT
     */
    function jwt_check($jwt = '')
    {
        $status = JWT::check($jwt);
        if ($status == 200) {
            return true;
        }
        switch ($status) {
            case 100:
                return 'JWT不能为为空';
                break;

            case 101:
                return 'JWT不完整';
                break;

            case 102:
                return 'JWT签名不正确';
                break;

            case 103:
                return 'JWT Payload解析错误';
                break;

            case 104:
                return '没有获得启用时间';
                break;

            case 105:
                return '当前 JWT 还未启用';
                break;

            case 106:
                return '没有获取到过期时间';
                break;

            case 107:
                return 'JWT 过期';
                break;

            case 108:
                return '当前 JWT 中没有数据字段';
                break;

            default:
                # code...
                break;
        }
    }
}

/*
// TEST

// 创建JWT
$jwt = jwt_start(['id' => 1]);
echo "<br/><br/>创建JWT:<pre>";
var_dump($jwt);

// 检测JWT
$check = jwt_check($jwt);
echo "</pre><br/><br/>检测JWT:<pre>";
var_dump($check);

// 获取数据
$data = jwt_data($jwt);
echo "</pre><br/><br/>读取数据:<pre>";
var_dump($data);

// 设置数据
$newData = [
'id' => 2,
'username' => 'jwt'
];
$jwt = jwt_set($jwt, $newData);
echo "</pre><br/><br/>修改ID添加USERNAME:<pre>";
var_dump($jwt);

// 检测JWT
$check = jwt_check($jwt);
echo "</pre><br/><br/>检测JWT:<pre>";
var_dump($check);

// 获取数据
$data = jwt_data($jwt);
echo "</pre><br/><br/>获取修改后的数据:<pre>";
var_dump($data);

// 获取username
$username = jwt_get($jwt, 'username');
echo "</pre><br/><br/>获取添加的数据USERNAME:<pre>";
var_dump($username);
echo "</pre>";
 */
