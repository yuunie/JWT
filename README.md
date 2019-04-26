# JWT

一个简单的JWT验证，使用方式还有点像Session

## 开始

包使用PSR-4自动加载并已经提交到Packagist，你可以使用Composer安装

```
composer require yuunie/jwt
```

## 环境

* PHP 7+

## 教程

### 自动加载

### 引入加载

* 如果你没有使用框架
* 使用以下方法引入

```
<?php
include_once 'verdor/autoload.php';
```

### 静态方法使用

#### 设置KEY

```
Yuunie\JWT::setKey('这里填写一个256个字符的串');
```
  
  * KEY是为了保护JWT签名所用
  * 不可泄露
  * 在同一个JWT验证环境中保持一致
  * 如果不使用该方法，可以直接在文件中配置修改，位置在JWT.php -> init() -> $key 同位置上方设置过期时间
  * 在每一次使用JWT之前都应该设置（如果没有在文件中修改）

* 生成JWT

```
$jwt = Yuunie\JWT::start(['id' => 1, 'username' => 'Fuck']);
```

  * $jwt将得到一个带有数据的JWT字符串

* 更新或修改JWT中的数据

```
$newJwt = Yuunie\JWT::set($jwt, ['username' => 'hello', 'sex' => 'none']);
```

  * $newJwt将得到修改和增加数据后的JWT字符串



#### 获得JWT中的所有用户添加的数据

```
$data = Yuunie\JWT::getData($jwt);
```
  
  * 正常返回一个数组
  * 否则返回false



#### 获得JWT中的用户添加的指定数据

```
$id = Yuunie\JWT::get($jwt, 'id');
```

  * 正常返回该数据
  * 否则返回false



#### 检测JWT是否正确

```
$info = Yuunie\JWT::check($jwt);
```

  * 默认情况下在获取信息或设置信息的时候都会自动检测JWT字符串
  * 但无论任何错误都会是返回false
  * 如果需要准确的错误信息请使用
  * 返回值为整数 200 => 一切正常



#### 错误值

```
switch ($info) {
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
        return '正常';
        break;
}
```

### Helper

```
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
```
